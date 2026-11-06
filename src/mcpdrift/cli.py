"""mcpdrift command line: snapshot an MCP server's surface, check it for drift."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

from . import __version__
from .canon import diff_raw, diff_surfaces, sha256_of, surface_digests
from .client import PROTOCOL_VERSION, MCPError, fetch_surface, surface_from_file
from .render import render_github, render_json, render_markdown, render_text, stop_commands
from .risk import SEVERITIES, Assessed, assess_changes, max_severity, rank, scan_surface
from .sign import SignError, sign_lock, verify_lock

OK_EXIT = 0
DRIFT_EXIT = 1
USAGE_EXIT = 2
INTEGRITY_EXIT = 3
LOCKFILE_VERSION = 2


def load_servers(config_path: str) -> Dict[str, Dict[str, Any]]:
    """Read a Claude-Desktop-style or plain {name: server} config."""
    try:
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"mcpdrift: config not found: {config_path}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SystemExit(f"mcpdrift: config is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise SystemExit("mcpdrift: config must be a JSON object")
    servers = data.get("mcpServers") or data.get("servers") or data
    if not isinstance(servers, dict) or not servers:
        raise SystemExit("mcpdrift: no servers found in config")
    return {k: v for k, v in servers.items() if isinstance(v, dict)}


def pick_server(servers: Dict[str, Dict[str, Any]], name: str | None) -> Dict[str, Any]:
    if name is None:
        if len(servers) == 1:
            return next(iter(servers.values()))
        raise SystemExit(
            "mcpdrift: config has several servers, name one with --server: "
            + ", ".join(sorted(servers))
        )
    if name not in servers:
        raise SystemExit(f"mcpdrift: server {name!r} not in config (have: {', '.join(sorted(servers))})")
    return servers[name]


def _live_surface(args: argparse.Namespace, server_name: Optional[str]) -> Dict[str, Any]:
    if getattr(args, "from_file", None):
        return surface_from_file(args.from_file)
    if not args.config:
        raise SystemExit("mcpdrift: give --config (launch the server) or --from-file (saved listing)")
    server = pick_server(load_servers(args.config), server_name)
    return fetch_surface(server, timeout=args.timeout, protocol_version=args.protocol_version)


def _server_label(args: argparse.Namespace) -> str:
    if args.server:
        return args.server
    if getattr(args, "from_file", None):
        return os.path.splitext(os.path.basename(args.from_file))[0]
    return next(iter(load_servers(args.config)))


def _target_mode(path: str) -> int:
    """Keep an existing file's permissions; new files get 0644 minus umask
    (mkstemp alone would leave a committed lockfile at 0600)."""
    try:
        return os.stat(path).st_mode & 0o7777
    except OSError:
        umask = os.umask(0)
        os.umask(umask)
        return 0o644 & ~umask


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    mode = _target_mode(path)
    fd, tmp = tempfile.mkstemp(prefix=".mcpdrift-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_lock(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            lock = json.load(fh)
    except FileNotFoundError:
        raise _Exit(USAGE_EXIT, f"mcpdrift: lock not found: {path} (run `mcpdrift snapshot` first)")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise _Exit(USAGE_EXIT, f"mcpdrift: lock is not valid JSON: {e}")
    if not isinstance(lock, dict) or not isinstance(lock.get("surface", {}), dict):
        raise _Exit(USAGE_EXIT, "mcpdrift: lock has no surface object")
    return lock


class _Exit(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _check_integrity(lock: Dict[str, Any]) -> None:
    """A v2 lock records its own digest; a mismatch means the surface was
    hand-edited after the snapshot, so the lock no longer says what was
    reviewed."""
    digests = lock.get("digests")
    if isinstance(digests, dict) and "surface" in digests:
        actual = sha256_of(lock.get("surface", {}))
        if digests["surface"] != actual:
            raise _Exit(
                INTEGRITY_EXIT,
                "mcpdrift: lockfile surface does not match its recorded digest "
                "(edited by hand?). Re-run `mcpdrift snapshot` and review the diff.",
            )


def _read_signature(path: str) -> str:
    try:
        with open(path, "r", encoding="ascii", errors="strict") as fh:
            return fh.read(64 * 1024)
    except FileNotFoundError:
        raise _Exit(INTEGRITY_EXIT, f"mcpdrift: signature not found: {path}")
    except UnicodeDecodeError:
        raise _Exit(INTEGRITY_EXIT, f"mcpdrift: signature is not an armored SSH signature: {path}")


def _verify(args: argparse.Namespace, lock: Dict[str, Any]) -> Optional[str]:
    if not args.allowed_signers:
        return None
    sig_path = args.signature or (args.lock + ".sig")
    try:
        return verify_lock(lock, _read_signature(sig_path), args.allowed_signers, args.identity or "")
    except SignError as e:
        raise _Exit(INTEGRITY_EXIT, f"mcpdrift: {e}")


_SCAN = {"noun": "risk signal(s)"}
_SCAN_MD = {"noun": "risk signal(s)", "empty": "no risky text signals found"}


def _emit(items: List[Assessed], fmt: str, lock_path: str = "", extra: Optional[Dict[str, Any]] = None,
          scan: bool = False) -> None:
    kw = _SCAN if scan else {}
    if fmt == "json":
        sys.stdout.write(render_json(items, extra))
    elif fmt == "markdown":
        sys.stdout.write(render_markdown(items, **(_SCAN_MD if scan else {})))
    elif fmt == "github":
        sys.stdout.write(render_github(items, lock_path))
        sys.stdout.write(stop_commands(render_text(items, **kw)))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        sys.stdout.write(render_text(items, color=color, **kw))


def _append_markdown(path: Optional[str], items: List[Assessed], title: str, scan: bool = False) -> None:
    if path:
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(render_markdown(items, title=title, **(_SCAN_MD if scan else {})))


def _exit_for(items: List[Assessed], fail_on: str) -> int:
    if fail_on == "never" or not items:
        return OK_EXIT
    worst = max_severity(a.severity for a in items)
    return DRIFT_EXIT if worst is not None and rank(worst) >= rank(fail_on) else OK_EXIT


# --------------------------------------------------------------------------
# commands


def _previous_seq(path: Optional[str]) -> int:
    if not path or path == "-" or not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            prev = json.load(fh)
        seq = prev.get("seq", 0) if isinstance(prev, dict) else 0
        return seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0
    except (OSError, ValueError):
        return 0


def _check_rollback(lock: Dict[str, Any], prev_path: str) -> None:
    """Reject a lock that is older than (or forks from) the previous one."""
    prev = _read_lock(prev_path)
    p_seq, l_seq = prev.get("seq"), lock.get("seq")
    if p_seq is None:
        return  # previous lock predates sequence numbers: nothing to compare
    if not isinstance(l_seq, int) or isinstance(l_seq, bool):
        raise _Exit(INTEGRITY_EXIT, "mcpdrift: lockfile has no seq but the previous one does (rollback?)")
    if l_seq < p_seq:
        raise _Exit(INTEGRITY_EXIT, f"mcpdrift: lockfile seq {l_seq} is older than previous seq {p_seq} (rollback)")
    if l_seq == p_seq and sha256_of(lock.get("surface", {})) != sha256_of(prev.get("surface", {})):
        raise _Exit(INTEGRITY_EXIT, f"mcpdrift: lockfile reuses seq {l_seq} with a different surface")


def cmd_snapshot(args: argparse.Namespace) -> int:
    surface = _live_surface(args, args.server)
    lock = {
        "mcpdrift": __version__,
        "lockfile_version": LOCKFILE_VERSION,
        "seq": _previous_seq(args.out) + 1,
        "server": _server_label(args),
        "snapshot_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "digests": surface_digests(surface),
        "surface": surface,
    }
    # ensure_ascii keeps invisible / look-alike characters visible as \\uXXXX
    # escapes when the lockfile is reviewed in a pull request.
    text = json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.out and args.out != "-":
        _atomic_write(args.out, text)
        print(f"mcpdrift: wrote {args.out} ({len(surface.get('tools', {}))} tools)", file=sys.stderr)
        if args.sign_key:
            sig = sign_lock(lock, args.sign_key)
            _atomic_write(args.out + ".sig", sig)
            print(f"mcpdrift: signed -> {args.out}.sig", file=sys.stderr)
    else:
        if args.sign_key:
            raise _Exit(USAGE_EXIT, "mcpdrift: --sign-key needs --out FILE")
        sys.stdout.write(text)
    risky = [a for a in scan_surface(surface) if rank(a.severity) >= rank("high")]
    if risky:
        print(
            f"mcpdrift: warning: {len(risky)} risky text signal(s) in this surface; "
            "you are pinning it as trusted. Review with `mcpdrift scan`.",
            file=sys.stderr,
        )
    return OK_EXIT


def cmd_check(args: argparse.Namespace) -> int:
    lock = _read_lock(args.lock)
    _check_integrity(lock)
    verified = _verify(args, lock)
    if verified:
        print(f"mcpdrift: {verified}", file=sys.stderr)
    if args.previous_lock:
        _check_rollback(lock, args.previous_lock)
    live = _live_surface(args, args.server or lock.get("server") if not args.from_file else args.server)
    old = lock.get("surface", {})
    ignore = list(args.ignore or [])
    if args.ignore_file:
        try:
            with open(args.ignore_file, "r", encoding="utf-8") as fh:
                ignore += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except FileNotFoundError:
            raise _Exit(USAGE_EXIT, f"mcpdrift: ignore file not found: {args.ignore_file}")
    if args.json:
        # Legacy 0.1 output shape, kept byte-compatible for existing scripts.
        findings = diff_surfaces(old, live, ignore=ignore)
        print(json.dumps({"drift": bool(findings), "findings": findings}, indent=2))
        return DRIFT_EXIT if findings else OK_EXIT
    items = assess_changes(diff_raw(old, live, ignore=ignore), old, live)
    _emit(items, args.format, args.lock, extra={"lock": args.lock, "server": lock.get("server")})
    _append_markdown(args.markdown_out, items, f"mcpdrift: {lock.get('server') or 'server'}")
    return _exit_for(items, args.fail_on)


def cmd_scan(args: argparse.Namespace) -> int:
    if args.lock:
        lock = _read_lock(args.lock)
        _check_integrity(lock)
        surface = lock.get("surface", {})
    else:
        surface = _live_surface(args, args.server)
    items = scan_surface(surface)
    if args.format == "text" and not items:
        print("no risky text signals found")
    else:
        _emit(items, args.format, args.lock or "", scan=True)
    _append_markdown(args.markdown_out, items, "mcpdrift scan", scan=True)
    return _exit_for(items, args.fail_on)


def cmd_sign(args: argparse.Namespace) -> int:
    lock = _read_lock(args.lock)
    _check_integrity(lock)
    try:
        sig = sign_lock(lock, args.key)
    except SignError as e:
        raise _Exit(USAGE_EXIT, f"mcpdrift: {e}")
    out = args.out or (args.lock + ".sig")
    _atomic_write(out, sig)
    print(f"mcpdrift: signed {args.lock} -> {out}", file=sys.stderr)
    return OK_EXIT


def cmd_verify(args: argparse.Namespace) -> int:
    lock = _read_lock(args.lock)
    _check_integrity(lock)
    print(f"mcpdrift: {_verify(args, lock)}")
    return OK_EXIT


# --------------------------------------------------------------------------
# argument parsing


def _source_args(p: argparse.ArgumentParser, config_required: bool = False) -> None:
    p.add_argument("--config", help="JSON config with mcpServers (e.g. .mcp.json); launches the server")
    p.add_argument("--from-file", metavar="FILE",
                   help="read a saved tools/list (or bundle) JSON instead of launching anything")
    p.add_argument("--server", help="server name inside the config (required if several)")
    p.add_argument("--timeout", type=float, default=20.0, help="seconds per request (default 20)")
    p.add_argument("--protocol-version", default=PROTOCOL_VERSION,
                   help=f"MCP protocol version to request (default {PROTOCOL_VERSION})")


def _output_args(p: argparse.ArgumentParser, default_fail: str) -> None:
    p.add_argument("--format", choices=("text", "json", "markdown", "github"), default="text",
                   help="output format; 'github' adds workflow annotations")
    p.add_argument("--fail-on", choices=SEVERITIES + ("never",), default=default_fail,
                   help=f"exit 1 only when a finding is at least this severe (default {default_fail})")
    p.add_argument("--markdown-out", metavar="FILE",
                   help="also append a markdown report here (e.g. $GITHUB_STEP_SUMMARY)")


def _verify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--allowed-signers", metavar="FILE",
                   help="OpenSSH allowed_signers file; when given, the lock signature must verify")
    p.add_argument("--identity", help="signer identity to require (e.g. you@example.com)")
    p.add_argument("--signature", metavar="FILE", help="signature path (default: <lock>.sig)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mcpdrift",
        description="Pin an MCP server's tool surface in a lockfile; fail CI when it drifts.",
        epilog="exit codes: 0 ok, 1 drift at/above --fail-on, 2 usage or server error, "
               "3 lockfile integrity or signature failure",
    )
    ap.add_argument("--version", action="version", version=f"mcpdrift {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="record the server's current surface to a lockfile")
    _source_args(s)
    s.add_argument("--out", default="-", help="lockfile path (default: stdout)")
    s.add_argument("--sign-key", metavar="KEY", help="SSH private key to sign the lock (writes <out>.sig)")
    s.set_defaults(func=cmd_snapshot)

    c = sub.add_parser("check", help="diff the live surface against a lockfile; exit 1 on drift")
    _source_args(c)
    c.add_argument("--lock", required=True, help="lockfile produced by `snapshot`")
    c.add_argument("--ignore", action="append", help="glob pattern of paths to ignore (repeatable)")
    c.add_argument("--ignore-file", metavar="FILE", help="file of ignore globs, one per line, # comments")
    c.add_argument("--json", action="store_true", help="legacy 0.1 JSON shape (prefer --format json)")
    c.add_argument("--previous-lock", metavar="FILE",
                   help="the lock from the base branch; fail (exit 3) if this lock rolls its seq back")
    _output_args(c, "low")
    _verify_args(c)
    c.set_defaults(func=cmd_check)

    sc = sub.add_parser("scan", help="risk-scan a lock or live server for poisoned descriptions")
    _source_args(sc)
    sc.add_argument("--lock", help="scan this lockfile instead of a live server")
    _output_args(sc, "high")
    sc.set_defaults(func=cmd_scan)

    sg = sub.add_parser("sign", help="sign a lockfile with an SSH key (ssh-keygen -Y sign)")
    sg.add_argument("--lock", required=True)
    sg.add_argument("--key", required=True, help="SSH private key (e.g. ~/.ssh/id_ed25519)")
    sg.add_argument("--out", help="signature path (default: <lock>.sig)")
    sg.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify a lockfile's SSH signature")
    v.add_argument("--lock", required=True)
    _verify_args(v)
    v.set_defaults(func=cmd_verify)
    return ap


def _safe_streams() -> None:
    # A Windows console (cp1252) cannot encode every character a server may
    # put in a description; never crash on output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.cmd == "verify" and not args.allowed_signers:
        ap.error("verify needs --allowed-signers and --identity")
    if getattr(args, "config", None) and getattr(args, "from_file", None):
        ap.error("use either --config or --from-file, not both")
    try:
        return args.func(args)
    except MCPError as e:
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT
    except SignError as e:
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT
    except _Exit as e:
        print(str(e), file=sys.stderr)
        return e.code
    except BrokenPipeError:  # output piped into `head` etc.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return DRIFT_EXIT  # output was cut short: fail closed, never claim "clean"
    except OSError as e:  # unwritable --out, unreadable file, ...
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
