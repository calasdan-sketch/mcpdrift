"""MCP Streamable HTTP client (stdlib only): enough to enumerate a remote
server's surface the same way the stdio client does.

Safety choices, because the config that names the URL may come from a pull
request:

* ``https`` only. Plain ``http`` is accepted for loopback hosts, or when the
  caller passes ``allow_insecure=True``.
* Redirects are never followed, so credentials cannot be bounced to another
  host.
* Header values may reference ``${VAR}`` only for variable names the caller
  explicitly allows (``--allow-env``). A pull request that edits the config
  therefore cannot read arbitrary CI secrets into a request.
* Responses are size-capped, and a server that never answers times out.

The legacy HTTP+SSE transport (a GET stream announcing an ``endpoint``) is
not implemented; it is reported with a clear error.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import time
from typing import Any, Dict, Iterable, Optional, Set
from urllib.parse import urlsplit

from .canon import DuplicateKeyError, strict_loads
from .client import MAX_LINE_BYTES, MAX_TOTAL_BYTES, MCPError, MCPHTTPError, rpc_error

LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def expand_header(value: str, allow_env: Iterable[str], environ: Optional[Dict[str, str]] = None) -> str:
    """Expand ``${NAME}`` in a header value, only for allowed names."""
    allowed = set(allow_env)
    env = os.environ if environ is None else environ

    def sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        if name not in allowed:
            raise MCPError(
                f"header references ${{{name}}} but it is not allowed; pass --allow-env {name} "
                "(only do this for configs you trust, e.g. from the base branch)"
            )
        if name not in env:
            raise MCPError(f"environment variable {name} (used in a header) is not set")
        return env[name]

    return _VAR.sub(sub, value)


class HttpMCP:
    """Same surface as ``StdioMCP``: request / notify / close."""

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 20.0,
        allow_env: Iterable[str] = (),
        allow_insecure: bool = False,
        environ: Optional[Dict[str, str]] = None,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise MCPError(f"not a valid http(s) URL: {url!r}")
        if parts.username or parts.password:
            raise MCPError("credentials inside the URL are not supported; use headers with --allow-env")
        if "${" in url:
            raise MCPError("environment expansion is not allowed in the URL")
        if parts.scheme == "http" and parts.hostname not in LOOPBACK and not allow_insecure:
            raise MCPError("refusing plain http to a non-loopback host (use https, or --allow-insecure-http)")
        self.parts = parts
        self.timeout = timeout
        self._id = 0
        self.session_id: Optional[str] = None
        self.negotiated: Optional[str] = None
        self.notifications: Set[str] = set()
        self._headers: Dict[str, str] = {}
        for k, v in (headers or {}).items():
            k = str(k)
            if not _HEADER_NAME.match(k):
                raise MCPError(f"invalid header name {k!r}")
            if k.lower() in ("host", "content-length", "content-type", "accept", "mcp-session-id",
                             "transfer-encoding", "connection"):
                raise MCPError(f"header {k!r} is managed by mcpdrift and cannot be set")
            self._headers[k] = expand_header(str(v), allow_env, environ)
        self._total = 0

    # -- plumbing ---------------------------------------------------------

    def _conn(self) -> http.client.HTTPConnection:
        p = self.parts
        port = p.port
        host = p.hostname or ""
        if p.scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                               context=ssl.create_default_context())
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _path(self) -> str:
        p = self.parts
        return (p.path or "/") + (("?" + p.query) if p.query else "")

    def _hdrs(self, with_body: bool = True) -> Dict[str, str]:
        h = dict(self._headers)
        h["Accept"] = "application/json, text/event-stream"
        if with_body:
            h["Content-Type"] = "application/json"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.negotiated:
            h["MCP-Protocol-Version"] = self.negotiated
        return h

    def _post(self, payload: Dict[str, Any]) -> http.client.HTTPResponse:
        conn = self._conn()
        try:
            conn.request("POST", self._path(), body=json.dumps(payload).encode("utf-8"), headers=self._hdrs())
            resp = conn.getresponse()
        except ValueError as e:  # bad header value (e.g. newline)
            conn.close()
            raise MCPError(f"invalid request header: {e}") from e
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise MCPError(f"cannot reach {self.parts.netloc}: {e}") from e
        resp._mcpdrift_conn = conn  # type: ignore[attr-defined]
        return resp

    def _hint(self, status: int) -> str:
        if status in (404, 405):
            return (" (legacy HTTP+SSE servers are not supported; if this is one, save a tools/list "
                    "response and use --from-file)")
        if status in (401, 403):
            return " (authentication failed; set a header in the config and pass --allow-env VAR)"
        return ""

    def _read_body(self, resp: http.client.HTTPResponse, limit: int) -> bytes:
        body = resp.read(limit + 1)
        if len(body) > limit:
            raise MCPError(f"server sent a message larger than {limit} bytes")
        self._total += len(body)
        if self._total > MAX_TOTAL_BYTES:
            raise MCPError(f"server sent more than {MAX_TOTAL_BYTES} bytes in total; refusing to continue")
        return body

    def _note(self, msg: Any) -> None:
        if isinstance(msg, dict) and "id" not in msg and isinstance(msg.get("method"), str):
            self.notifications.add(msg["method"][:100])

    def _sse_message(self, resp: http.client.HTTPResponse, want_id: int) -> Optional[Dict[str, Any]]:
        data_lines: list = []
        deadline = time.monotonic() + self.timeout

        def flush() -> Optional[Dict[str, Any]]:
            if not data_lines:
                return None
            raw = "\n".join(data_lines)
            data_lines.clear()
            try:
                msg = strict_loads(raw)
            except DuplicateKeyError as e:
                raise MCPError(f"server sent JSON that {e}; refusing to guess which value it meant") from None
            except (ValueError, RecursionError):
                return None
            for m in (msg if isinstance(msg, list) else [msg]):
                self._note(m)
                if isinstance(m, dict) and m.get("id") == want_id and ("result" in m or "error" in m):
                    return m
            return None

        while True:
            if time.monotonic() > deadline:
                raise MCPError("timeout reading event stream")
            try:
                line = resp.readline(MAX_LINE_BYTES + 1)
            except (OSError, http.client.HTTPException) as e:
                raise MCPError(f"event stream failed: {e}") from e
            if not line:
                return flush()
            if len(line) > MAX_LINE_BYTES:
                raise MCPError(f"server sent a message larger than {MAX_LINE_BYTES} bytes")
            self._total += len(line)
            if self._total > MAX_TOTAL_BYTES:
                raise MCPError(f"server sent more than {MAX_TOTAL_BYTES} bytes in total; refusing to continue")
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text == "":
                found = flush()
                if found is not None:
                    return found
            elif text.startswith("data:"):
                data_lines.append(text[5:].lstrip(" "))

    # -- API --------------------------------------------------------------

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._id += 1
        rid = self._id
        resp = self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        conn = resp._mcpdrift_conn  # type: ignore[attr-defined]
        try:
            if 300 <= resp.status < 400:
                raise MCPError(f"{method}: server redirected (HTTP {resp.status}); redirects are not followed")
            if resp.status >= 400:
                self._read_body(resp, 4096)
                raise MCPHTTPError(f"{method}: HTTP {resp.status}{self._hint(resp.status)}")
            sid = resp.getheader("Mcp-Session-Id")
            if sid and method == "initialize":
                if not re.fullmatch(r"[\x21-\x7e]{1,256}", sid):
                    raise MCPError("server sent an invalid Mcp-Session-Id")
                self.session_id = sid
            ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if ctype == "text/event-stream":
                data = self._sse_message(resp, rid)
                if data is None:
                    raise MCPError(f"{method}: event stream ended without a response")
            else:
                body = self._read_body(resp, MAX_LINE_BYTES)
                try:
                    data = strict_loads(body.decode("utf-8", "replace"))
                except DuplicateKeyError as e:
                    raise MCPError(f"server sent JSON that {e}; refusing to guess which value it meant") from None
                except (ValueError, RecursionError):
                    raise MCPError(f"{method}: response is not JSON ({ctype or 'no content-type'})") from None
                if isinstance(data, list):  # a batch: find ours
                    for m in data:
                        self._note(m)
                    data = next((m for m in data if isinstance(m, dict) and m.get("id") == rid), None)
                if not isinstance(data, dict) or data.get("id") != rid:
                    raise MCPError(f"{method}: response did not match the request")
        finally:
            conn.close()
        if "error" in data:
            raise rpc_error(method, data["error"])
        result = data.get("result")
        if method == "initialize" and isinstance(result, dict):
            pv = result.get("protocolVersion")
            if isinstance(pv, str) and re.fullmatch(r"[0-9A-Za-z.\-]{1,32}", pv):
                self.negotiated = pv
        return result if isinstance(result, dict) else {}

    def notify(self, method: str) -> None:
        conn = self._conn()
        try:
            conn.request("POST", self._path(), body=json.dumps({"jsonrpc": "2.0", "method": method}).encode(),
                         headers=self._hdrs())
            resp = conn.getresponse()
            resp.read(4096)
            if resp.status >= 400:
                raise MCPError(f"{method}: HTTP {resp.status}{self._hint(resp.status)}")
        except ValueError as e:
            raise MCPError(f"invalid request header: {e}") from e
        except (OSError, http.client.HTTPException) as e:
            raise MCPError(f"cannot reach {self.parts.netloc}: {e}") from e
        finally:
            conn.close()

    def stderr_tail(self) -> str:
        return ""

    def close(self) -> None:
        if not self.session_id:
            return
        conn = self._conn()
        try:
            conn.request("DELETE", self._path(), headers=self._hdrs(with_body=False))
            conn.getresponse().read(1024)
        except Exception:
            pass
        finally:
            conn.close()
