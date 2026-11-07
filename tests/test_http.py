"""Streamable HTTP client against a local in-process server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcpdrift.cli import main
from mcpdrift.client import MCPError, fetch_capture
from mcpdrift.http_client import HttpMCP, expand_header

TOOLS = [{"name": "t%d" % i, "description": "tool %d" % i, "inputSchema": {"type": "object"}} for i in range(5)]


def make_server(mode="json", page=2, status=None, calls=None):
    seen = {"headers": [], "deleted": False, "count": 0}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_DELETE(self):
            seen["deleted"] = True
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["headers"].append({k.lower(): v for k, v in self.headers.items()})
            if status:
                self.send_response(status)
                self.send_header("Location", "http://127.0.0.1:1/")
                self.end_headers()
                return
            if "id" not in body:
                self.send_response(202)
                self.end_headers()
                return
            m = body["method"]
            hdr = {}
            if m == "initialize":
                res = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "h", "version": "1"}}
                hdr["Mcp-Session-Id"] = "sess-123"
            elif m == "tools/list":
                seen["count"] += 1
                cur = (body.get("params") or {}).get("cursor")
                start = int(cur) if cur else 0
                res = {"tools": TOOLS[start:start + page]}
                if start + page < len(TOOLS):
                    res["nextCursor"] = str(start + page)
            else:
                out = json.dumps({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "nf"}})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(out.encode())
                return
            payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": res})
            self.send_response(200)
            for k, v in hdr.items():
                self.send_header(k, v)
            if mode == "sse":
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                note = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
                self.wfile.write(f"event: message\ndata: {note}\n\n".encode())
                self.wfile.write(f"event: message\ndata: {payload}\n\n".encode())
            else:
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload.encode())

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/mcp", seen


@pytest.fixture
def stop():
    servers = []
    yield servers.append
    for s in servers:
        s.shutdown()


@pytest.mark.parametrize("mode", ["json", "sse"])
def test_fetch_paginated_over_http(mode, stop):
    srv, url, seen = make_server(mode)
    stop(srv)
    cap = fetch_capture({"type": "http", "url": url}, timeout=5, samples=2)
    assert sorted(cap.surface["tools"]) == [t["name"] for t in TOOLS]
    assert len(cap.samples) == 2
    later = seen["headers"][-1]
    assert later.get("mcp-session-id") == "sess-123"
    assert later.get("mcp-protocol-version") == "2025-03-26"
    assert seen["deleted"]
    if mode == "sse":
        assert "notifications/tools/list_changed" in cap.notifications


def test_end_to_end_cli_over_http(tmp_path, stop):
    srv, url, _ = make_server()
    stop(srv)
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"mcpServers": {"h": {"url": url}}}))
    lock = str(tmp_path / "l.json")
    assert main(["snapshot", "--config", str(cfg), "--out", lock]) == 0
    assert main(["check", "--config", str(cfg), "--lock", lock]) == 0
    TOOLS.append({"name": "extra", "description": "x", "inputSchema": {"type": "object"}})
    try:
        assert main(["check", "--config", str(cfg), "--lock", lock]) == 1
    finally:
        TOOLS.pop()


def test_redirect_is_not_followed(stop):
    srv, url, _ = make_server(status=302)
    stop(srv)
    with pytest.raises(MCPError, match="redirect"):
        fetch_capture({"url": url}, timeout=5)


def test_plain_http_to_remote_host_refused():
    with pytest.raises(MCPError, match="plain http"):
        HttpMCP("http://example.com/mcp")
    HttpMCP("http://localhost:1/mcp")  # loopback ok
    HttpMCP("http://example.com/mcp", allow_insecure=True)


def test_url_credentials_and_expansion_refused():
    with pytest.raises(MCPError, match="credentials"):
        HttpMCP("https://u:p@example.com/mcp")
    with pytest.raises(MCPError, match="expansion"):
        HttpMCP("https://example.com/${X}")


def test_header_env_expansion_is_allow_listed():
    env = {"TOK": "abc", "OTHER": "zzz"}
    assert expand_header("Bearer ${TOK}", ["TOK"], env) == "Bearer abc"
    with pytest.raises(MCPError, match="not allowed"):
        expand_header("Bearer ${OTHER}", ["TOK"], env)
    with pytest.raises(MCPError, match="not set"):
        expand_header("${NOPE}", ["NOPE"], env)


def test_header_injection_and_reserved_headers_refused():
    with pytest.raises(MCPError, match="invalid header name"):
        HttpMCP("https://example.com/", headers={"X\r\nEvil": "1"})
    with pytest.raises(MCPError, match="managed"):
        HttpMCP("https://example.com/", headers={"Mcp-Session-Id": "1"})
    c = HttpMCP("https://example.com/", headers={"X-A": "1\r\nX-Evil: 1"})
    with pytest.raises(MCPError):
        c.request("initialize")


def test_sse_legacy_type_has_clear_error():
    with pytest.raises(MCPError, match="legacy"):
        fetch_capture({"type": "sse", "url": "https://example.com/sse"})


def test_server_with_secret_in_header_gets_it(stop, monkeypatch):
    srv, url, seen = make_server()
    stop(srv)
    monkeypatch.setenv("MY_TOK", "s3cret")
    fetch_capture({"url": url, "headers": {"Authorization": "Bearer ${MY_TOK}"}}, timeout=5, allow_env=["MY_TOK"])
    assert seen["headers"][0]["authorization"] == "Bearer s3cret"
    with pytest.raises(MCPError, match="not allowed"):
        fetch_capture({"url": url, "headers": {"Authorization": "Bearer ${MY_TOK}"}}, timeout=5)
