"""Minimal MCP stdio client: enough to enumerate a server's exposed surface.

Speaks newline-delimited JSON-RPC 2.0 over stdin/stdout, the MCP stdio
transport. Only the calls needed for a surface snapshot are implemented.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from typing import Any, Dict, List

from .canon import build_surface

PROTOCOL_VERSION = "2024-11-05"


class MCPError(RuntimeError):
    """Server rejected a call, closed the pipe, or timed out."""


class StdioMCP:
    def __init__(
        self,
        command: List[str],
        env: Dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> None:
        if not command:
            raise MCPError("server command is empty")
        merged = dict(os.environ)
        merged.update(env or {})
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - user's own config
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                env=merged,
            )
        except OSError as e:
            raise MCPError(f"cannot start {command[0]!r}: {e}") from e
        self.timeout = timeout
        self._id = 0
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put("")  # EOF sentinel

    def _send(self, payload: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
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
                raise MCPError(f"timeout waiting for {method}")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise MCPError(f"timeout waiting for {method}") from None
            if line == "":
                raise MCPError("server closed stdout")
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate non-JSON chatter on stdout
            if not isinstance(data, dict) or data.get("id") != self._id:
                continue
            if "error" in data:
                raise MCPError(f"{method}: {data['error']}")
            result = data.get("result")
            return result if isinstance(result, dict) else {}

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def _list_or_empty(client: StdioMCP, method: str) -> List[Dict[str, Any]]:
    """List a capability; servers without it answer method-not-found -> empty."""
    try:
        result = client.request(method)
    except MCPError:
        return []
    key = {"tools/list": "tools", "resources/list": "resources", "prompts/list": "prompts"}[method]
    items = result.get(key, [])
    return [x for x in items if isinstance(x, dict)]


def fetch_surface(server: Dict[str, Any], timeout: float = 20.0) -> Dict[str, Any]:
    """Launch an MCP stdio server from config and snapshot its surface."""
    command = server.get("command")
    if isinstance(command, str):
        command = [command]
    args = [str(a) for a in server.get("args", [])]
    client = StdioMCP(
        [str(command[0])] + list(command[1:]) + args,
        env={str(k): str(v) for k, v in (server.get("env") or {}).items()},
        timeout=timeout,
    )
    try:
        init = client.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcpdrift", "version": "0.1.0"},
            },
        )
        client.notify("notifications/initialized")
        tools = _list_or_empty(client, "tools/list")
        resources = _list_or_empty(client, "resources/list")
        prompts = _list_or_empty(client, "prompts/list")
        return build_surface(init, tools, resources, prompts)
    finally:
        client.close()
