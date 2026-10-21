"""mcpdrift command line: snapshot an MCP server's surface, check it for drift."""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from typing import Any, Dict

from . import __version__
from .canon import diff_surfaces
from .client import MCPError, fetch_surface

USAGE_EXIT = 2


def load_servers(config_path: str) -> Dict[str, Dict[str, Any]]:
    """Read a Claude-Desktop-style or plain {name: server} config."""
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"mcpdrift: config not found: {config_path}")
    except json.JSONDecodeError as e:
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


def cmd_snapshot(args: argparse.Namespace) -> int:
    server = pick_server(load_servers(args.config), args.server)
    surface = fetch_surface(server, timeout=args.timeout)
    lock = {
        "mcpdrift": __version__,
        "server": args.server or next(iter(load_servers(args.config))),
        "snapshot_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "surface": surface,
    }
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    if args.out and args.out != "-":
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"mcpdrift: wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        with open(args.lock, "r", encoding="utf-8") as fh:
            lock = json.load(fh)
    except FileNotFoundError:
        print(f"mcpdrift: lock not found: {args.lock} (run `mcpdrift snapshot` first)", file=sys.stderr)
        return USAGE_EXIT
    server = pick_server(load_servers(args.config), args.server or lock.get("server"))
    live = fetch_surface(server, timeout=args.timeout)
    findings = diff_surfaces(lock.get("surface", {}), live, ignore=args.ignore or [])
    if args.json:
        print(json.dumps({"drift": bool(findings), "findings": findings}, indent=2))
    elif not findings:
        print("no drift")
    else:
        for kind, path, detail in findings:
            print(f"{kind:8} {path}: {detail}")
        print(f"\n{len(findings)} drift finding(s)", file=sys.stderr)
    return 1 if findings else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcpdrift",
        description="Pin an MCP server's tool surface in a lockfile; fail CI when it drifts.",
    )
    ap.add_argument("--version", action="version", version=f"mcpdrift {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="record the server's current surface to a lockfile")
    s.add_argument("--config", required=True, help="JSON config with mcpServers (e.g. .mcp.json)")
    s.add_argument("--server", help="server name inside the config (required if several)")
    s.add_argument("--out", default="-", help="lockfile path (default: stdout)")
    s.add_argument("--timeout", type=float, default=20.0)
    s.set_defaults(func=cmd_snapshot)

    c = sub.add_parser("check", help="diff the live surface against a lockfile; exit 1 on drift")
    c.add_argument("--config", required=True)
    c.add_argument("--server", help="defaults to the server recorded in the lockfile")
    c.add_argument("--lock", required=True, help="lockfile produced by `snapshot`")
    c.add_argument("--ignore", action="append", help="glob pattern of paths to ignore (repeatable)")
    c.add_argument("--json", action="store_true", help="machine-readable findings")
    c.add_argument("--timeout", type=float, default=20.0)
    c.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except MCPError as e:
        print(f"mcpdrift: {e}", file=sys.stderr)
        return USAGE_EXIT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
