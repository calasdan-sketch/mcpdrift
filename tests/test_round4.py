"""Round 4: the first hour of a stranger, plus fail-closed listing errors."""
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import mcpdrift
from mcpdrift import cli
from mcpdrift.cli import main
from mcpdrift.client import MCPError, fetch_capture

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A stdio server whose tools/list misbehaves in a chosen way.
SERVER = r'''
import json, sys, time
mode, caps = sys.argv[1], json.loads(sys.argv[2])
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    m = msg["method"]
    def reply(**kw):
        print(json.dumps(dict(jsonrpc="2.0", id=msg["id"], **kw)), flush=True)
    if m == "initialize":
        reply(result={"protocolVersion": "2025-06-18", "capabilities": caps, "serverInfo": {"name": "s", "version": "1"}})
    elif m == "tools/list":
        if mode == "hang":
            time.sleep(60)
        elif mode == "exit":
            sys.exit(3)
        elif mode == "rpcerror":
            reply(error={"code": -32000, "message": "boom"})
        elif mode == "notfound":
            reply(error={"code": -32601, "message": "nope"})
        else:
            reply(result={"tools": [{"name": "t", "description": "d", "inputSchema": {"type": "object"}}]})
    else:
        reply(error={"code": -32601, "message": "nope"})
'''


def cfg(tmp_path, mode, caps=None, name="s"):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"mcpServers": {name: {"command": [sys.executable, "-c", SERVER, mode,
                                                              json.dumps(caps if caps is not None else {"tools": {}})]}}}))
    return str(p)


# --- a listing that fails is an error, never "no tools" -----------------------

@pytest.mark.parametrize("mode", ["hang", "exit", "rpcerror"])
def test_failed_tools_listing_is_an_error_not_an_empty_surface(tmp_path, mode, capsys):
    out = str(tmp_path / "l.json")
    rc = main(["snapshot", "--config", cfg(tmp_path, mode), "--out", out, "--timeout", "2", "--samples", "1"])
    assert rc == 2
    assert not os.path.exists(out)  # nothing pinned
    assert "mcpdrift:" in capsys.readouterr().err


def test_method_not_found_means_empty_section(tmp_path):
    cap = fetch_capture(json.loads(open(cfg(tmp_path, "notfound")).read())["mcpServers"]["s"], timeout=5)
    assert cap.surface["tools"] == {}


def test_error_for_a_capability_the_server_did_not_advertise_is_empty(tmp_path):
    server = json.loads(open(cfg(tmp_path, "rpcerror", caps={})).read())["mcpServers"]["s"]
    assert fetch_capture(server, timeout=5).surface["tools"] == {}


def test_check_does_not_report_removed_tool_when_server_hangs(tmp_path, capsys):
    good = cfg(tmp_path, "ok")
    lock = str(tmp_path / "l.json")
    assert main(["snapshot", "--config", good, "--out", lock, "--timeout", "5"]) == 0
    capsys.readouterr()
    bad = cfg(tmp_path, "hang")
    rc = main(["check", "--config", bad, "--lock", lock, "--timeout", "1", "--fail-on", "critical"])
    assert rc == 2  # not 0 (a quiet pass) and not a fake "tool removed"
    assert "removed" not in capsys.readouterr().out


def _http(status_for_tools, other_status=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if "id" not in body:
                self.send_response(202)
                self.end_headers()
                return
            if body["method"] == "tools/list":
                if status_for_tools == 200:
                    data = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(status_for_tools)
                self.end_headers()
                return
            if other_status and body["method"] != "initialize":
                self.send_response(other_status)
                self.end_headers()
                return
            res = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "h"}}
            data = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": res}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_http_error_on_tools_listing_is_an_error():
    srv = _http(500)
    try:
        with pytest.raises(MCPError, match="HTTP 500"):
            fetch_capture({"url": f"http://127.0.0.1:{srv.server_port}/mcp"}, timeout=5)
    finally:
        srv.shutdown()


def test_http_404_for_a_section_the_server_never_advertised_is_empty():
    srv = _http(200, other_status=404)
    try:
        cap = fetch_capture({"url": f"http://127.0.0.1:{srv.server_port}/mcp"}, timeout=5)
        assert cap.surface["tools"] == {} and cap.surface["resources"] == {}
    finally:
        srv.shutdown()


# --- exit codes: a bad config is a usage error (2), never "drift" (1) ---------

def test_config_problems_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    for argv in (["snapshot", "--config", str(bad)], ["snapshot", "--config", str(tmp_path / "missing.json")],
                 ["snapshot"]):
        assert main(argv) == 2
    empty = tmp_path / "empty.json"
    empty.write_text('{"mcpServers": {}}')
    assert main(["snapshot", "--config", str(empty)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.count("mcpdrift:") >= 4


def test_renamed_single_server_still_checks_against_lock(tmp_path):
    lock = str(tmp_path / "l.json")
    assert main(["snapshot", "--config", cfg(tmp_path, "ok", name="old-name"), "--out", lock]) == 0
    assert main(["check", "--config", cfg(tmp_path, "ok", name="new-name"), "--lock", lock]) == 0
    # an explicit --server that does not exist is still an error
    assert main(["check", "--config", cfg(tmp_path, "ok", name="new-name"), "--lock", lock,
                 "--server", "ghost"]) == 2


def test_ctrl_c_is_never_a_clean_exit(monkeypatch, capsys):
    def boom(args):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "cmd_demo", boom)
    assert main(["demo"]) == 130
    assert "interrupted" in capsys.readouterr().err


# --- writing files -----------------------------------------------------------

def test_write_to_missing_folder_is_plain_english(tmp_path, capsys):
    out = tmp_path / "nope" / "x.lock"
    rc = main(["snapshot", "--from-file", os.path.join(ROOT, "src", "mcpdrift", "examples", "notes-v1.json"),
               "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does not exist" in err and ".mcpdrift-" not in err
    assert not list(tmp_path.glob(".mcpdrift-*"))


def test_replace_retries_on_windows(monkeypatch, tmp_path):
    calls = []
    real = os.replace

    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("held open")
        real(a, b)
    src, dst = tmp_path / "a", tmp_path / "b"
    src.write_text("x")
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(os, "replace", flaky)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    cli._replace(str(src), str(dst))
    assert len(calls) == 3 and dst.read_text() == "x"


def test_color_off_on_unknown_windows_console(monkeypatch):
    class TTY:
        def isatty(self):
            return True
    monkeypatch.setattr(cli.sys, "stdout", TTY())
    for k in ("NO_COLOR", "WT_SESSION", "ANSICON", "ConEmuANSI", "TERM_PROGRAM", "COLORTERM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(os, "name", "nt")
    assert cli._use_color() is False
    monkeypatch.setenv("WT_SESSION", "1")
    assert cli._use_color() is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli._use_color() is False


def test_sarif_uri_inside_cwd_stays_relative(monkeypatch, tmp_path):
    from mcpdrift.render import _sarif_uri
    monkeypatch.chdir(tmp_path)
    assert _sarif_uri(str(tmp_path / "sub" / "mcp.lock.json")) == "sub/mcp.lock.json"
    assert _sarif_uri("/somewhere/else/mcp.lock.json") == "mcp.lock.json"
    assert _sarif_uri("..\\x\\mcp.lock.json") == "mcp.lock.json"


# --- the stranger's first hour -----------------------------------------------

def test_demo_runs_from_the_installed_package(capsys, tmp_path):
    assert main(["demo"]) == 0
    cap = capsys.readouterr()
    assert "CRITICAL" in cap.out and "6 drift finding(s)" in cap.out
    keep = tmp_path / "kept"
    assert main(["demo", "--dir", str(keep)]) == 0
    assert (keep / "demo.lock.json").exists() and (keep / "notes-v2.json").exists()


def test_packaged_files_exist():
    pkg = os.path.dirname(mcpdrift.__file__)
    assert os.path.exists(os.path.join(pkg, "py.typed"))
    for n in ("notes-v1.json", "notes-v2.json"):
        json.load(open(os.path.join(pkg, "examples", n)))


def test_version_is_one_number_everywhere():
    v = mcpdrift.__version__
    changelog = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    assert re.search(rf"^## {re.escape(v)}\b", changelog, re.M)
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert 'dynamic = ["version"]' in pyproject and "mcpdrift.__version__" in pyproject
    assert not re.search(r"^version\s*=\s*\"", pyproject, re.M)


def test_docs_have_no_invisible_characters():
    bad = re.compile("[​-‏‪-‮⁦-⁩﻿]")
    for name in ("README.md", "CHANGELOG.md", "action.yml", "pyproject.toml"):
        text = open(os.path.join(ROOT, name), encoding="utf-8").read()
        assert not bad.search(text), name


def test_readme_quick_start_commands_are_real_subcommands():
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    subs = set(cli.build_parser()._subparsers._group_actions[0].choices)
    in_fence, seen = False, 0
    for line in readme.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        elif in_fence:
            m = re.match(r"(?:\$ )?mcpdrift (\w[\w-]*)", line)
            if m:
                seen += 1
                assert m.group(1) in subs, line
    assert seen >= 4
    assert {"demo", "snapshot", "check", "scan", "update", "diff", "sign", "verify"} <= subs


def test_lock_from_a_newer_mcpdrift_is_refused(tmp_path, capsys):
    ex = os.path.join(ROOT, "src", "mcpdrift", "examples", "notes-v1.json")
    lock = tmp_path / "l.json"
    assert main(["snapshot", "--from-file", ex, "--out", str(lock)]) == 0
    data = json.loads(lock.read_text())
    for bad in (99, "x", True):
        data["lockfile_version"] = bad
        lock.write_text(json.dumps(data))
        assert main(["check", "--from-file", ex, "--lock", str(lock)]) == 2
    assert "Upgrade mcpdrift" in capsys.readouterr().err


def test_lock_defaults_to_mcp_lock_json(tmp_path, monkeypatch):
    ex = os.path.join(ROOT, "src", "mcpdrift", "examples", "notes-v1.json")
    monkeypatch.chdir(tmp_path)
    assert main(["snapshot", "--from-file", ex, "--out", "mcp.lock.json"]) == 0
    assert main(["check", "--from-file", ex]) == 0
    assert main(["update", "--from-file", ex]) == 0


def test_importing_main_module_does_not_run_the_cli():
    import importlib
    importlib.import_module("mcpdrift.__main__")  # would raise SystemExit if it ran


def test_python_dash_m_works(tmp_path):
    import subprocess
    r = subprocess.run([sys.executable, "-m", "mcpdrift", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == f"mcpdrift {mcpdrift.__version__}"


def test_find_exe_never_uses_the_current_folder_on_windows(tmp_path, monkeypatch):
    from mcpdrift._exe import find_exe
    here, sysdir = tmp_path / "repo", tmp_path / "bin"
    here.mkdir()
    sysdir.mkdir()
    (here / "ssh-keygen.exe").write_text("planted")
    (sysdir / "ssh-keygen.exe").write_text("real")
    monkeypatch.chdir(here)
    path = os.pathsep.join([".", str(here), str(sysdir)])
    got = find_exe("ssh-keygen", path=path, windows=True, pathext=".exe;.cmd")
    assert got == str(sysdir / "ssh-keygen.exe")
    assert find_exe("ssh-keygen", path=os.pathsep.join([".", str(here)]), windows=True, pathext=".exe") is None
