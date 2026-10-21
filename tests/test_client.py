"""End-to-end tests: snapshot and check against a fake MCP stdio server."""
import json
import sys

import pytest

from mcpdrift.canon import diff_surfaces
from mcpdrift.client import MCPError, fetch_surface

FAKE_SERVER = r'''
import json, sys
TOOLS = json.loads(sys.argv[1])
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method = msg.get("method", "")
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "1.2.3"}}}))
    elif method == "tools/list":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}))
    elif method in ("resources/list", "prompts/list"):
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}))
    elif "id" in msg:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                          "error": {"code": -32601, "message": "method not found"}}))
    sys.stdout.flush()
'''

TOOLS = [
    {"name": "search", "description": "search things",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
]


def server_cmd(tools):
    return [sys.executable, "-c", FAKE_SERVER, json.dumps(tools)]


def test_fetch_surface_from_fake_server():
    surface = fetch_surface({"command": server_cmd(TOOLS)}, timeout=15)
    assert surface["server"]["name"] == "fake"
    assert "search" in surface["tools"]


def test_server_version_bump_is_visible():
    # same tools, fake server always reports 1.2.3 — surface equality holds
    a = fetch_surface({"command": server_cmd(TOOLS)}, timeout=15)
    b = fetch_surface({"command": server_cmd(list(TOOLS))}, timeout=15)
    assert diff_surfaces(a, b) == []


def test_changed_toolset_detected():
    a = fetch_surface({"command": server_cmd(TOOLS)}, timeout=15)
    grown = TOOLS + [{"name": "write", "description": "write a doc",
                      "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}}]
    b = fetch_surface({"command": server_cmd(grown)}, timeout=15)
    assert any(k == "added" and p == "tools.write" for k, p, d in diff_surfaces(a, b))


def test_missing_binary_raises():
    with pytest.raises(MCPError):
        fetch_surface({"command": ["/definitely/not/a/binary"]}, timeout=5)


def test_env_passthrough():
    # server that echoes an env var through its serverInfo name
    src = (
        "import json,os,sys\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if m.get('method')=='initialize':\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'protocolVersion':'2024-11-05','capabilities':{},'serverInfo':{'name':os.environ.get('TAG','none'),'version':'0'}}}))\n"
        " elif 'id' in m:\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{}}))\n"
        " sys.stdout.flush()\n"
    )
    s = fetch_surface({"command": [sys.executable, "-c", src], "env": {"TAG": "fromenv"}}, timeout=15)
    assert s["server"]["name"] == "fromenv"
