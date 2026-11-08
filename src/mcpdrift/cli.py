"""mcpdrift command line: snapshot an MCP server's surface, check it for drift."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .canon import SurfaceError, diff_surfaces, sha256_of, strict_load, surface_digests
from .client import PROTOCOL_VERSION, Capture, MCPError, fetch_capture, surface_from_file
from .render import (render_github, render_junit, render_json, render_markdown, render_sarif, render_text,
                     stop_commands)
from .review import Prepared, dynamic_items, footprint, prepare, stability_items
from .risk import SEVERITIES, Assessed, max_severity, rank, scan_surface
from .sign import SignError, sign_lock, verify_lock

OK_EXIT = 0
DRIFT_EXIT = 1
USAGE_EXIT = 2
INTEGRITY_EXIT = 3
LOCKFILE_VERSION = 2
MAX_HISTORY = 50
DEFAULT_LOCK = "mcp.lock.json"


def load_servers(config_path: str) -> Dict[str, Dict[str, Any]]:
    """Read a Claude-Desktop-style or plain {name: server} config."""
    try:
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            data = strict_load(fh)
    except FileNotFoundError:
        raise _Exit(USAGE_EXIT, f"mcpdrift: config not found: {config_path}")
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
        raise _Exit(USAGE_EXIT, f"mcpdrift: config is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise _Exit(USAGE_EXIT, "mcpdrift: config must be a JSON object")
    servers = data.get("mcpServers") or data.get("servers") or data
    if not isinstance(servers, dict) or not servers:
        raise _Exit(USAGE_EXIT, "mcpdrift: no servers found in config")
    found = {k: v for k, v in servers.items() if isinstance(v, dict)}
    if not found:
        raise _Exit(USAGE_EXIT, "mcpdrift: no servers found in config")
    return found


def pick_server(servers: Dict[str, Dict[str, Any]], name: str | None, soft: bool = False) -> Dict[str, Any]:
    """``soft``: ``name`` came from a lockfile, not from the user; a config with
    exactly one server is then used even if it was renamed."""
    if name is None:
        if len(servers) == 1:
            return next(iter(servers.values()))
        raise _Exit(USAGE_EXIT, "mcpdrift: config has several servers, name one with --server: "
                    + ", ".join(sorted(servers)))
    if name not in servers:
        if soft and len(servers) == 1:
            return next(iter(servers.values()))
        raise _Exit(USAGE_EXIT, f"mcpdrift: server {name!r} not in config (have: {', '.join(sorted(servers))})")
    return servers[name]


def _capture(args: argparse.Namespace, server_name: Optional[str], soft: bool = False) -> Capture:
    if getattr(args, "from_file", None):
        surf = surface_from_file(args.from_file)
        return Capture(surf, [surf])
    if not args.config:
        raise _Exit(USAGE_EXIT, "mcpdrift: give --config (launch the server) or --from-file (saved listing)")
    server = pick_server(load_servers(args.config), server_name, soft and not args.server)
    allow_env: List[str] = []
    for item in args.allow_env or []:
        allow_env += [x.strip() for x in item.split(",") if x.strip()]
    return fetch_capture(server, timeout=args.timeout, protocol_version=args.protocol_version,
                         samples=args.samples, allow_env=allow_env, allow_insecure=args.allow_insecure_http,
                         isolate_env=getattr(args, "isolate_env", False))


def _live_surface(args: argparse.Namespace, server_name: Optional[str], soft: bool = False) -> Dict[str, Any]:
    return _capture(args, server_name, soft).surface


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


def _replace(tmp: str, path: str) -> None:
    """``os.replace`` with a short retry: on Windows it fails with
    PermissionError while another process (an editor, a virus scanner) holds
    the destination open for a moment."""
    attempts = 6 if os.name == "nt" else 1
    for i in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.05 * (i + 1))


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        raise _Exit(USAGE_EXIT, f"mcpdrift: cannot write {path}: the folder {d} does not exist")
    mode = _target_mode(path)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".mcpdrift-", dir=d)
    except OSError as e:
        raise _Exit(USAGE_EXIT, f"mcpdrift: cannot write {path}: {e.strerror or e}") from e
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        _replace(tmp, path)
    except BaseException as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(e, OSError):
            raise _Exit(USAGE_EXIT, f"mcpdrift: cannot write {path}: {e.strerror or e}") from e
        raise


def _read_lock(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            lock = strict_load(fh)
    except FileNotFoundError:
        raise _Exit(USAGE_EXIT, f"mcpdrift: lock not found: {path} (run `mcpdrift snapshot` first)")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise _Exit(USAGE_EXIT, f"mcpdrift: lock is not valid JSON: {e}")
    if not isinstance(lock, dict) or not isinstance(lock.get("surface", {}), dict):
        raise _Exit(USAGE_EXIT, "mcpdrift: lock has no surface object")
    ver = lock.get("lockfile_version", 1)
    if not isinstance(ver, int) or isinstance(ver, bool) or ver > LOCKFILE_VERSION:
        raise _Exit(USAGE_EXIT, f"mcpdrift: {path} has lockfile_version {str(ver)[:20]!r}, newer than this "
                                f"mcpdrift understands ({LOCKFILE_VERSION}). Upgrade mcpdrift (pip install -U mcpdrift); "
                                "comparing it anyway could hide a change.")
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


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return fh.read()
    except OSError:
        return ""


def _use_color() -> bool:
    """Colour only on a real terminal. A legacy Windows console prints raw
    escape codes, so there it needs a terminal known to understand them."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return any(os.environ.get(k) for k in ("WT_SESSION", "ANSICON", "ConEmuANSI", "TERM_PROGRAM", "COLORTERM"))
    return True


def _emit(items: List[Assessed], fmt: str, lock_path: str = "", extra: Optional[Dict[str, Any]] = None,
          scan: bool = False, fail_on: str = "low") -> None:
    kw: Dict[str, Any] = _SCAN if scan else {}
    if fmt == "junit":
        sys.stdout.write(render_junit(items, "mcpdrift scan" if scan else "mcpdrift", fail_on, __version__))
    elif fmt == "sarif":
        sys.stdout.write(render_sarif(items, lock_path, _read_text(lock_path) if lock_path else "", __version__))
    elif fmt == "json":
        sys.stdout.write(render_json(items, extra))
    elif fmt == "markdown":
        sys.stdout.write(render_markdown(items, **(_SCAN_MD if scan else {})))
    elif fmt == "github":
        sys.stdout.write(render_github(items, lock_path))
        sys.stdout.write(stop_commands(render_text(items, **kw)))
    else:
        color = _use_color()
        sys.stdout.write(render_text(items, color=color, **kw))


def _write_junit(path: Optional[str], items: List[Assessed], fail_on: str, scan: bool = False) -> None:
    if path:
        _atomic_write(path, render_junit(items, "mcpdrift scan" if scan else "mcpdrift", fail_on, __version__))


def _write_sarif(path: Optional[str], items: List[Assessed], lock_path: str = "") -> None:
    if path:
        _atomic_write(path, render_sarif(items, lock_path, _read_text(lock_path) if lock_path else "",
                                         __version__))


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
            prev = strict_load(fh)
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


def _now() -> str:
    """UTC time for lock stamps. ``SOURCE_DATE_EPOCH`` (the reproducible-builds
    convention) pins it so two snapshots of one surface are byte-identical."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", "")
    when = None
    if raw.isascii() and raw.isdigit() and len(raw) <= 11:
        try:
            when = datetime.datetime.fromtimestamp(int(raw), datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            when = None
    return (when or datetime.datetime.now(datetime.timezone.utc)).isoformat(timespec="seconds")


def _build_lock(args: argparse.Namespace, surface: Dict[str, Any], out: Optional[str],
                history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    lock: Dict[str, Any] = {
        "mcpdrift": __version__,
        "lockfile_version": LOCKFILE_VERSION,
        "seq": _previous_seq(out) + 1,
        "server": _server_label(args),
        "snapshot_at": _now(),
        "digests": surface_digests(surface),
        "surface": surface,
    }
    if history:
        lock["history"] = history[-MAX_HISTORY:]
    return lock


def _warn_risky(surface: Dict[str, Any]) -> None:
    risky = [a for a in scan_surface(surface) if rank(a.severity) >= rank("high")]
    if risky:
        print(
            f"mcpdrift: warning: {len(risky)} risky text signal(s) in this surface; "
            "you are pinning it as trusted. Review with `mcpdrift scan`.",
            file=sys.stderr,
        )


def _unstable_refusal(cap: Capture, strict: bool, ignore: Sequence[str] = ()) -> Optional[List[Assessed]]:
    items = stability_items(cap.samples, strict, ignore)
    return items or None


def cmd_snapshot(args: argparse.Namespace) -> int:
    cap = _capture(args, args.server)
    surface = cap.surface
    if not args.allow_unstable:
        unstable = _unstable_refusal(cap, False, _ignore_list(args))
        if unstable:
            sys.stdout.write(render_text(unstable))
            print("mcpdrift: the server returned different listings within one session; refusing to pin a "
                  "surface that is not stable (use --allow-unstable to pin the first listing anyway)",
                  file=sys.stderr)
            return DRIFT_EXIT
    lock = _build_lock(args, surface, args.out)
    # ensure_ascii keeps invisible / look-alike characters visible as \\uXXXX
    # escapes when the lockfile is reviewed in a pull request.
    text = json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.out and args.out != "-":
        _atomic_write(args.out, text)
        print(f"mcpdrift: wrote {args.out} ({len(surface.get('tools', {}))} tools, "
              f"{footprint(surface):,} characters of model-visible text)", file=sys.stderr)
        if args.sign_key:
            sig = sign_lock(lock, args.sign_key)
            _atomic_write(args.out + ".sig", sig)
            print(f"mcpdrift: signed -> {args.out}.sig", file=sys.stderr)
    else:
        if args.sign_key:
            raise _Exit(USAGE_EXIT, "mcpdrift: --sign-key needs --out FILE")
        sys.stdout.write(text)
    _warn_risky(surface)
    return OK_EXIT


def _ignore_list(args: argparse.Namespace) -> List[str]:
    ignore = list(getattr(args, "ignore", None) or [])
    if getattr(args, "ignore_file", None):
        try:
            with open(args.ignore_file, "r", encoding="utf-8") as fh:
                ignore += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except FileNotFoundError:
            raise _Exit(USAGE_EXIT, f"mcpdrift: ignore file not found: {args.ignore_file}")
    return ignore


def _prepare(args: argparse.Namespace, lock: Dict[str, Any]) -> Tuple[Prepared, Capture]:
    cap = _capture(args, args.server or lock.get("server") if not args.from_file else args.server, soft=True)
    prep = prepare(lock.get("surface", {}), cap.samples, cap.notifications, _ignore_list(args), args.strict)
    if prep.cosmetic_ignored:
        print(f"mcpdrift: {prep.cosmetic_ignored} cosmetic-only difference(s) ignored (reordered lists, "
              "whitespace); use --strict to see them", file=sys.stderr)
    return prep, cap


def cmd_check(args: argparse.Namespace) -> int:
    lock = _read_lock(args.lock)
    _check_integrity(lock)
    verified = _verify(args, lock)
    if verified:
        print(f"mcpdrift: {verified}", file=sys.stderr)
    if args.previous_lock:
        _check_rollback(lock, args.previous_lock)
    if args.json:
        # Legacy 0.1 output shape, kept byte-compatible for existing scripts.
        live = _live_surface(args, args.server or lock.get("server") if not args.from_file else args.server, True)
        findings = diff_surfaces(lock.get("surface", {}), live, ignore=_ignore_list(args))
        print(json.dumps({"drift": bool(findings), "findings": findings}, indent=2))
        return DRIFT_EXIT if findings else OK_EXIT
    prep, _cap = _prepare(args, lock)
    items = prep.items
    _emit(items, args.format, args.lock,
          extra={"lock": args.lock, "server": lock.get("server"), "review_token": prep.token,
                 "cosmetic_ignored": prep.cosmetic_ignored}, fail_on=args.fail_on)
    _append_markdown(args.markdown_out, items, f"mcpdrift: {lock.get('server') or 'server'}")
    _write_sarif(args.sarif_out, items, args.lock)
    _write_junit(args.junit_out, items, args.fail_on)
    code = _exit_for(items, args.fail_on)
    if items and args.format == "text":
        print(f"\nreview token: {prep.token}\n"
              f"to accept this exact drift after reading it: mcpdrift update --lock {args.lock} "
              f"--approve {prep.token} <same source options>", file=sys.stderr)
    return code


def _clean_name(text: Optional[str]) -> str:
    return "".join(c for c in (text or "") if c.isprintable())[:80]


def cmd_update(args: argparse.Namespace) -> int:
    """Re-pin after a human has read the drift. Never rewrites silently."""
    lock = _read_lock(args.lock)
    _check_integrity(lock)
    if args.allowed_signers:  # do not build on a lock that is not itself trusted
        print(f"mcpdrift: {_verify(args, lock)}", file=sys.stderr)
    prep, cap = _prepare(args, lock)
    if not prep.items and not prep.raw:
        print(f"mcpdrift: {args.lock} is already up to date", file=sys.stderr)
        return OK_EXIT
    worst = max_severity(a.severity for a in prep.items) or "info"
    approved = "token" if args.approve and args.approve == prep.token else None
    if args.approve and not approved:
        print(f"mcpdrift: --approve {args.approve} does not match the drift seen now ({prep.token}); "
              "the server changed since you reviewed it, or you approved a different run", file=sys.stderr)
    if approved is None and rank(worst) <= rank(args.auto_accept):
        approved = "auto"
    if approved is None or (prep.unstable and not args.allow_unstable):
        _emit(prep.items, "text")
        if prep.unstable and not args.allow_unstable:
            print("mcpdrift: the server is not stable within one session; refusing to re-pin "
                  "(--allow-unstable overrides)", file=sys.stderr)
        else:
            print(f"mcpdrift: not updated. Read the drift above, then re-run with --approve {prep.token}",
                  file=sys.stderr)
        return DRIFT_EXIT
    history: List[Any] = lock["history"] if isinstance(lock.get("history"), list) else []
    entry = {
        "seq": _previous_seq(args.lock) + 1,
        "at": _now(),
        "token": prep.token,
        "findings": len(prep.items),
        "max_severity": worst,
        "approved_by": approved if not args.approver else f"{approved}:{_clean_name(args.approver)}",
    }
    new = _build_lock(args, cap.surface, args.lock, [h for h in history if isinstance(h, dict)] + [entry])
    new["server"] = lock.get("server") or new["server"]
    _atomic_write(args.lock, json.dumps(new, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"mcpdrift: updated {args.lock} to seq {new['seq']} ({len(prep.items)} finding(s) accepted, "
          f"worst {worst})", file=sys.stderr)
    sig_path = args.lock + ".sig"
    if args.sign_key:
        _atomic_write(sig_path, sign_lock(new, args.sign_key))
        print(f"mcpdrift: signed -> {sig_path}", file=sys.stderr)
    elif os.path.exists(sig_path):
        print(f"mcpdrift: warning: {sig_path} is now stale; re-sign with `mcpdrift sign` "
              "(CI with --allowed-signers will fail until you do)", file=sys.stderr)
    _warn_risky(cap.surface)
    return OK_EXIT


def cmd_scan(args: argparse.Namespace) -> int:
    if args.lock:
        lock = _read_lock(args.lock)
        _check_integrity(lock)
        surface = lock.get("surface", {})
        extra: List[Assessed] = []
    else:
        cap = _capture(args, args.server)
        surface = cap.surface
        extra = stability_items(cap.samples, False, _ignore_list(args)) + dynamic_items(cap.notifications)
    items = scan_surface(surface) + extra
    if args.format == "text" and not items:
        print("no risky text signals found")
    else:
        _emit(items, args.format, args.lock or "", scan=True, fail_on=args.fail_on)
    _append_markdown(args.markdown_out, items, "mcpdrift scan", scan=True)
    _write_sarif(args.sarif_out, items, args.lock or "")
    _write_junit(args.junit_out, items, args.fail_on, scan=True)
    return _exit_for(items, args.fail_on)


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two lockfiles with no server involved (e.g. a PR's lock
    against the base branch's lock)."""
    old, new = _read_lock(args.old), _read_lock(args.new)
    for lk in (old, new):
        _check_integrity(lk)
    prep = prepare(old.get("surface", {}), [new.get("surface", {})], (), _ignore_list(args), args.strict)
    _emit(prep.items, args.format, args.new,
          extra={"lock": args.new, "server": new.get("server"), "review_token": prep.token,
                 "cosmetic_ignored": prep.cosmetic_ignored}, fail_on=args.fail_on)
    _append_markdown(args.markdown_out, prep.items, f"mcpdrift diff: {new.get('server') or 'server'}")
    _write_sarif(args.sarif_out, prep.items, args.new)
    _write_junit(args.junit_out, prep.items, args.fail_on)
    return _exit_for(prep.items, args.fail_on)


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the 10-second example on listings that ship inside the package, so
    it works after a plain ``pip install`` (nothing is launched or sent)."""
    from importlib import resources

    base = resources.files("mcpdrift") / "examples"
    with tempfile.TemporaryDirectory(prefix="mcpdrift-demo-") as tmp:
        work = args.dir or tmp
        if args.dir:
            os.makedirs(work, exist_ok=True)
        paths = {}
        for name in ("notes-v1.json", "notes-v2.json"):
            paths[name] = os.path.join(work, name)
            _atomic_write(paths[name], (base / name).read_text(encoding="utf-8"))
        lock = os.path.join(work, "demo.lock.json")
        steps = [
            ["snapshot", "--from-file", paths["notes-v1.json"], "--out", lock],
            ["check", "--from-file", paths["notes-v2.json"], "--lock", lock],
        ]
        print("mcpdrift demo: step 1, pin the surface of notes server v1 (a saved listing; nothing is run)",
              file=sys.stderr)
        rc = main(steps[0])
        if rc != OK_EXIT:
            return rc
        print("\nmcpdrift demo: step 2, check a later release of the server against that pin", file=sys.stderr)
        rc = main(steps[1])
        print(f"\nmcpdrift demo: the check exited {rc} (1 means drift was found, which is what this example shows). "
              "Your own server: mcpdrift snapshot --config .mcp.json --out mcp.lock.json", file=sys.stderr)
        if args.dir:
            print(f"mcpdrift demo: files kept in {work}", file=sys.stderr)
    return OK_EXIT if rc == DRIFT_EXIT else USAGE_EXIT


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
    p.add_argument("--samples", type=int, default=3, metavar="N",
                   help="list the surface N times in one session (1-10, default 3) to catch servers that "
                        "answer differently on later calls")
    p.add_argument("--allow-env", action="append", metavar="NAME",
                   help="environment variable a remote server's headers may reference as ${NAME} "
                        "(repeatable; only for configs you trust)")
    p.add_argument("--isolate-env", action="store_true",
                   help="start a stdio server with only a minimal environment (PATH, HOME, TEMP, ...) plus the "
                        "config's own 'env', so it cannot read your CI secrets")
    p.add_argument("--allow-insecure-http", action="store_true",
                   help="allow plain http:// to a non-loopback host (not recommended)")


def _output_args(p: argparse.ArgumentParser, default_fail: str) -> None:
    p.add_argument("--format", choices=("text", "json", "markdown", "github", "sarif", "junit"),
                   default="text", help="output format; 'github' adds workflow annotations")
    p.add_argument("--fail-on", choices=SEVERITIES + ("never",), default=default_fail,
                   help=f"exit 1 only when a finding is at least this severe (default {default_fail})")
    p.add_argument("--markdown-out", metavar="FILE",
                   help="also append a markdown report here (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--sarif-out", metavar="FILE", help="also write a SARIF 2.1.0 report here (code scanning)")
    p.add_argument("--junit-out", metavar="FILE", help="also write a JUnit XML report here (CI test reports)")


def _verify_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--allowed-signers", metavar="FILE",
                   help="OpenSSH allowed_signers file; when given, the lock signature must verify")
    p.add_argument("--identity", help="signer identity to require (e.g. you@example.com)")
    p.add_argument("--signature", metavar="FILE", help="signature path (default: <lock>.sig)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mcpdrift",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Pin an MCP server's tool surface in a lockfile; fail CI when it drifts.",
        epilog="mcpdrift is maintained by Calas Automations Inc.\n"
               "exit codes: 0 ok, 1 drift at/above --fail-on, 2 usage or server error, "
               "3 lockfile integrity or signature failure",
    )
    ap.add_argument("--version", action="version", version=f"mcpdrift {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="record the server's current surface to a lockfile")
    _source_args(s)
    s.add_argument("--out", default="-", help="lockfile path (default: stdout)")
    s.add_argument("--sign-key", metavar="KEY", help="SSH private key to sign the lock (writes <out>.sig)")
    s.add_argument("--allow-unstable", action="store_true",
                   help="pin even if the server answered differently within one session")
    s.add_argument("--ignore", action="append",
                   help="glob of paths allowed to differ between listings of one session, e.g. '**._meta' "
                        "(repeatable). The lock still stores what the server sent; pass the same --ignore to check")
    s.add_argument("--ignore-file", metavar="FILE", help="file of ignore globs, one per line, # comments")
    s.set_defaults(func=cmd_snapshot)

    c = sub.add_parser("check", help="diff the live surface against a lockfile; exit 1 on drift")
    _source_args(c)
    c.add_argument("--lock", default=DEFAULT_LOCK, help=f"lockfile produced by `snapshot` (default {DEFAULT_LOCK})")
    c.add_argument("--ignore", action="append", help="glob pattern of paths to ignore (repeatable)")
    c.add_argument("--ignore-file", metavar="FILE", help="file of ignore globs, one per line, # comments")
    c.add_argument("--json", action="store_true", help="legacy 0.1 JSON shape (prefer --format json)")
    c.add_argument("--previous-lock", metavar="FILE",
                   help="the lock from the base branch; fail (exit 3) if this lock rolls its seq back")
    _output_args(c, "low")
    _verify_args(c)
    c.add_argument("--strict", action="store_true",
                   help="compare raw JSON; do not ignore reordered lists or whitespace-only changes")
    c.set_defaults(func=cmd_check)

    u = sub.add_parser("update", help="re-pin the lock after reviewing drift (needs --approve TOKEN)")
    _source_args(u)
    u.add_argument("--lock", default=DEFAULT_LOCK, help=f"lockfile to update in place (default {DEFAULT_LOCK})")
    u.add_argument("--approve", metavar="TOKEN", help="review token printed by `check` for the drift you read")
    u.add_argument("--auto-accept", choices=SEVERITIES, default="info",
                   help="accept drift up to this severity without a token (default info: version bumps)")
    u.add_argument("--approver", help="free-text name recorded in the lock's history")
    u.add_argument("--ignore", action="append", help="glob pattern of paths to ignore (repeatable)")
    u.add_argument("--ignore-file", metavar="FILE")
    u.add_argument("--strict", action="store_true", help="compare raw JSON")
    u.add_argument("--sign-key", metavar="KEY", help="re-sign the updated lock with this SSH key")
    u.add_argument("--allow-unstable", action="store_true", help="re-pin even if the server is unstable")
    _verify_args(u)
    u.set_defaults(func=cmd_update)

    d = sub.add_parser("diff", help="compare two lockfiles (no server is contacted)")
    d.add_argument("old", help="the trusted lockfile (e.g. from the base branch)")
    d.add_argument("new", help="the lockfile to review")
    d.add_argument("--ignore", action="append", help="glob pattern of paths to ignore (repeatable)")
    d.add_argument("--ignore-file", metavar="FILE")
    d.add_argument("--strict", action="store_true", help="compare raw JSON")
    _output_args(d, "low")
    d.set_defaults(func=cmd_diff)

    sc = sub.add_parser("scan", help="risk-scan a lock or live server for poisoned descriptions")
    _source_args(sc)
    sc.add_argument("--lock", help="scan this lockfile instead of a live server")
    sc.add_argument("--ignore", action="append", help="glob of paths allowed to differ between listings (repeatable)")
    sc.add_argument("--ignore-file", metavar="FILE", help="file of ignore globs, one per line, # comments")
    _output_args(sc, "high")
    sc.set_defaults(func=cmd_scan)

    dm = sub.add_parser("demo", help="try it: pin an example server, then check a poisoned update (no server is run)")
    dm.add_argument("--dir", metavar="DIR", help="keep the example files in DIR instead of a temporary folder")
    dm.set_defaults(func=cmd_demo)

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
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
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
    except (SignError, SurfaceError) as e:
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT
    except _Exit as e:
        print(str(e), file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print("mcpdrift: interrupted", file=sys.stderr)
        return 130  # never a clean exit
    except BrokenPipeError:  # output piped into `head` etc.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return DRIFT_EXIT  # output was cut short: fail closed, never claim "clean"
    except OSError as e:  # unwritable --out, unreadable file, ...
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT
    except Exception as e:  # noqa: BLE001 - a bug or hostile input: never a clean exit, never a traceback in CI
        print(f"mcpdrift: internal error ({type(e).__name__}: {str(e)[:200]}); treating as failure. "
              "Please report it with the listing that triggered it.", file=sys.stderr)
        return USAGE_EXIT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
