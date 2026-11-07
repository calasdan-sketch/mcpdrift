"""Minimal MCP stdio client: enough to enumerate a server's exposed surface.

Speaks newline-delimited JSON-RPC 2.0 over stdin/stdout, the MCP stdio
transport. Only the calls needed for a surface snapshot are implemented.
"""
from __future__ import annotations

import collections
import json
import os
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Set

from .canon import build_surface

# Kept at the long-standing revision so existing lockfiles stay stable; servers
# negotiate, and newer fields (outputSchema, annotations, title) are returned
# by current SDKs regardless. Override with --protocol-version.
PROTOCOL_VERSION = "2024-11-05"

# Hard limits so a hostile or broken server cannot exhaust memory or loop.
MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # across all pages of all listings
MAX_PAGES = 1000
MAX_ITEMS = 50_000
STDERR_TAIL = 20


def _sanitize(line: str) -> str:
    """Server stderr is untrusted: drop control characters and defuse
    "::" so it cannot forge GitHub Actions workflow commands."""
    line = "".join(c if c.isprintable() else "?" for c in line)
    return line.replace("::", ": :")


class MCPError(RuntimeError):
    """Server rejected a call, closed the pipe, or timed out."""


class StdioMCP:
    def __init__(
        self,
        command: List[str],
        env: Dict[str, str] | None = None,
        timeout: float = 20.0,
        cwd: str | None = None,
    ) -> None:
        if not command:
            raise MCPError("server command is empty")
        merged = dict(os.environ)
        merged.update(env or {})
        # Resolve through PATH (and PATHEXT on Windows) so "npx" finds
        # npx.cmd; subprocess without a shell would not.
        resolved = shutil.which(command[0], path=merged.get("PATH"))
        if resolved:
            command = [resolved] + list(command[1:])
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - user's own config
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=merged,
                cwd=cwd,
            )
        except OSError as e:
            raise MCPError(f"cannot start {command[0]!r}: {e}") from e
        self.timeout = timeout
        self._id = 0
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._stderr: Deque[str] = collections.deque(maxlen=STDERR_TAIL)
        self.notifications: set = set()  # method names of server notifications seen
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self._err_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._err_reader.start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        total = 0
        while True:
            raw = self.proc.stdout.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            total += len(raw)
            if len(raw) > MAX_LINE_BYTES:
                self._lines.put("\x00too-long")
                break
            if total > MAX_TOTAL_BYTES:
                self._lines.put("\x00too-much")
                break
            self._lines.put(raw.decode("utf-8", "replace"))
        self._lines.put("")  # EOF sentinel

    def _pump_stderr(self) -> None:
        # Drained continuously so a chatty server never blocks on a full pipe;
        # the tail is shown when something fails.
        assert self.proc.stderr is not None
        for raw in iter(lambda: self.proc.stderr.readline(65536), b""):
            self._stderr.append(_sanitize(raw.decode("utf-8", "replace").rstrip())[:500])

    def stderr_tail(self) -> str:
        lines = [x for x in list(self._stderr) if x]
        return ("\n  server stderr:\n    " + "\n    ".join(lines[-8:])) if lines else ""

    def _send(self, payload: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise MCPError(f"server pipe closed: {e}") from e

    def request(self, method: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPError(f"timeout waiting for {method}" + self.stderr_tail())
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise MCPError(f"timeout waiting for {method}" + self.stderr_tail()) from None
            if line == "":
                self._err_reader.join(timeout=1.0)  # collect the crash message
                raise MCPError("server closed stdout" + self.stderr_tail())
            if line == "\x00too-long":
                raise MCPError(f"server sent a message larger than {MAX_LINE_BYTES} bytes")
            if line == "\x00too-much":
                raise MCPError(f"server sent more than {MAX_TOTAL_BYTES} bytes in total; refusing to continue")
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue  # tolerate non-JSON chatter on stdout
            if isinstance(data, dict) and "id" not in data and isinstance(data.get("method"), str):
                self.notifications.add(data["method"][:100])
            if not isinstance(data, dict) or data.get("id") != self._id:
                continue
            if "error" in data:
                raise MCPError(f"{method}: {data['error']}")
            result = data.get("result")
            return result if isinstance(result, dict) else {}

    def notify(self, method: str) -> None:  # noqa: D401
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                pass


LIST_KEYS = {"tools/list": "tools", "resources/list": "resources", "prompts/list": "prompts"}


def _list_or_empty(client: "StdioMCP", method: str) -> List[Dict[str, Any]]:
    """List a capability, following ``nextCursor`` pagination.

    Servers without the capability answer method-not-found, which yields an
    empty list. A failure on a *later* page is an error, not a silent
    truncation: a half-read surface would make the lock lie.
    """
    key = LIST_KEYS[method]
    items: List[Dict[str, Any]] = []
    cursor = None
    seen = set()
    for page in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor is not None else None
        try:
            result = client.request(method, params)
        except MCPError:
            if page == 0:
                return []
            raise
        batch = result.get(key, [])
        if isinstance(batch, list):
            items.extend(x for x in batch if isinstance(x, dict))
        if len(items) > MAX_ITEMS:
            raise MCPError(f"{method}: more than {MAX_ITEMS} entries; refusing to continue")
        cursor = result.get("nextCursor")
        if cursor is None or cursor == "":
            return items
        if not isinstance(cursor, str) or cursor in seen:
            raise MCPError(f"{method}: server returned a repeating or invalid nextCursor")
        seen.add(cursor)
    raise MCPError(f"{method}: more than {MAX_PAGES} pages")


def is_remote(server: Dict[str, Any]) -> bool:
    return not server.get("command") and bool(server.get("url") or server.get("type") in ("http", "sse", "streamable-http"))


def server_command(server: Dict[str, Any]) -> List[str]:
    command = server.get("command")
    if isinstance(command, str):
        command = [command]
    if not isinstance(command, list) or not command:
        raise MCPError("server has no 'command'")
    args = server.get("args") or []
    if not isinstance(args, list):
        raise MCPError("server 'args' must be a list")
    return [str(c) for c in command] + [str(a) for a in args]


@dataclass
class Capture:
    """What a live session returned: the first surface, every later sample,
    and the notification methods the server sent."""

    surface: Dict[str, Any]
    samples: List[Dict[str, Any]] = field(default_factory=list)  # samples[0] is surface
    notifications: Set[str] = field(default_factory=set)


MAX_SAMPLES = 10


def _open(server: Dict[str, Any], timeout: float, allow_env: Iterable[str], allow_insecure: bool):
    if is_remote(server):
        from .http_client import HttpMCP

        if server.get("type") == "sse":
            raise MCPError("legacy HTTP+SSE servers (type 'sse') are not supported; use a Streamable HTTP "
                           "URL, or save a tools/list response and use --from-file")
        url = server.get("url")
        if not isinstance(url, str):
            raise MCPError("server 'url' must be a string")
        hdrs = server.get("headers") or {}
        if not isinstance(hdrs, dict):
            raise MCPError("server 'headers' must be an object")
        return HttpMCP(url, headers=hdrs, timeout=timeout, allow_env=allow_env, allow_insecure=allow_insecure)
    env = server.get("env") or {}
    if not isinstance(env, dict):
        raise MCPError("server 'env' must be an object")
    cwd = server.get("cwd")
    return StdioMCP(
        server_command(server),
        env={str(k): str(v) for k, v in env.items()},
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
    )


def fetch_capture(
    server: Dict[str, Any],
    timeout: float = 20.0,
    protocol_version: str = PROTOCOL_VERSION,
    samples: int = 1,
    allow_env: Iterable[str] = (),
    allow_insecure: bool = False,
) -> Capture:
    """Launch (stdio) or connect to (Streamable HTTP) a server and list its
    surface ``samples`` times in one session, so a server that answers
    differently on later calls (a call-count "time bomb") is visible."""
    if not isinstance(samples, int) or isinstance(samples, bool) or not 1 <= samples <= MAX_SAMPLES:
        raise MCPError(f"samples must be between 1 and {MAX_SAMPLES}")
    client = _open(server, timeout, allow_env, allow_insecure)
    try:
        from . import __version__

        init = client.request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "mcpdrift", "version": __version__},
            },
        )
        client.notify("notifications/initialized")
        taken: List[Dict[str, Any]] = []
        for _ in range(samples):
            tools = _list_or_empty(client, "tools/list")
            resources = _list_or_empty(client, "resources/list")
            prompts = _list_or_empty(client, "prompts/list")
            taken.append(build_surface(init, tools, resources, prompts))
        return Capture(taken[0], taken, set(client.notifications))
    finally:
        client.close()


def fetch_surface(
    server: Dict[str, Any],
    timeout: float = 20.0,
    protocol_version: str = PROTOCOL_VERSION,
) -> Dict[str, Any]:
    """Snapshot a server's surface once (kept for library users)."""
    return fetch_capture(server, timeout, protocol_version).surface


def surface_from_file(path: str) -> Dict[str, Any]:
    """Build a surface from saved JSON instead of launching a server.

    Accepts any of:
      * a raw ``tools/list`` result: ``{"tools": [...]}`` (optionally with
        ``resources`` / ``prompts`` lists alongside),
      * a JSON-RPC response wrapping one: ``{"result": {"tools": [...]}}``,
      * a bundle: ``{"initialize": {...}, "tools": [...], "resources": [...], "prompts": [...]}``,
      * a bare list of tool objects.

    Nothing is executed, which makes this the safe way to vet an untrusted
    server's listing in CI.
    """
    try:
        if os.path.getsize(path) > MAX_TOTAL_BYTES:
            raise MCPError(f"listing file is larger than {MAX_TOTAL_BYTES} bytes")
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise MCPError(f"listing file not found: {path}") from None
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
        raise MCPError(f"listing file is not valid JSON: {e}") from None
    if isinstance(data, list):
        data = {"tools": data}
    if not isinstance(data, dict):
        raise MCPError("listing file must be a JSON object or list")
    if isinstance(data.get("result"), dict):
        data = data["result"]

    def lst(key: str) -> List[Dict[str, Any]]:
        v = data.get(key)
        if isinstance(v, dict) and isinstance(v.get(key), list):
            v = v[key]  # {"tools": {"tools": [...]}} from a saved tools/list result
        return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []

    init = data.get("initialize")
    if not isinstance(init, dict):
        init = {k: data[k] for k in ("serverInfo", "capabilities") if k in data}
    return build_surface(init, lst("tools"), lst("resources"), lst("prompts"))
