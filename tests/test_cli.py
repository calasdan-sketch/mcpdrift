"""CLI-level tests: snapshot writes a lock, check exits 1 on drift."""
import json

import pytest

from mcpdrift.cli import main
from tests.test_client import TOOLS, server_cmd


def write_config(tmp_path, tools, name="demo"):
    cfg = tmp_path / f"{name}.mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"demo": {"command": server_cmd(tools)}}}), encoding="utf-8")
    return str(cfg)


def test_snapshot_then_check_clean(tmp_path, capsys):
    cfg = write_config(tmp_path, TOOLS)
    lock = str(tmp_path / "mcp.lock.json")
    assert main(["snapshot", "--config", cfg, "--out", lock, "--timeout", "15"]) == 0
    data = json.loads((tmp_path / "mcp.lock.json").read_text(encoding="utf-8"))
    assert data["server"] == "demo" and "tools" in data["surface"]
    assert main(["check", "--config", cfg, "--lock", lock, "--timeout", "15"]) == 0
    assert "no drift" in capsys.readouterr().out


def test_check_exits_1_on_drift(tmp_path, capsys):
    cfg = write_config(tmp_path, TOOLS)
    lock = str(tmp_path / "mcp.lock.json")
    main(["snapshot", "--config", cfg, "--out", lock, "--timeout", "15"])
    grown = TOOLS + [{"name": "delete", "description": "danger", "inputSchema": {}}]
    cfg2 = write_config(tmp_path, grown, name="demo2")
    assert main(["check", "--config", cfg2, "--lock", lock, "--timeout", "15"]) == 1
    out = capsys.readouterr().out
    assert "tools.delete" in out


def test_check_ignore_pattern(tmp_path):
    cfg = write_config(tmp_path, TOOLS)
    lock = str(tmp_path / "mcp.lock.json")
    main(["snapshot", "--config", cfg, "--out", lock, "--timeout", "15"])
    grown = TOOLS + [{"name": "delete", "description": "d", "inputSchema": {}}]
    cfg2 = write_config(tmp_path, grown, name="demo2")
    assert main(["check", "--config", cfg2, "--lock", lock, "--ignore", "tools.delete", "--timeout", "15"]) == 0


def test_json_output(tmp_path, capsys):
    cfg = write_config(tmp_path, TOOLS)
    lock = str(tmp_path / "mcp.lock.json")
    main(["snapshot", "--config", cfg, "--out", lock, "--timeout", "15"])
    main(["check", "--config", cfg, "--lock", lock, "--json", "--timeout", "15"])
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"drift": False, "findings": []}


def test_missing_lock_is_usage_error(tmp_path, capsys):
    cfg = write_config(tmp_path, TOOLS)
    assert main(["check", "--config", cfg, "--lock", str(tmp_path / "nope.json")]) == 2


def test_unknown_server_is_usage_error(tmp_path, capsys):
    cfg = write_config(tmp_path, TOOLS)
    with pytest.raises(SystemExit):
        main(["snapshot", "--config", cfg, "--server", "ghost"])


def test_multi_server_requires_name(tmp_path):
    cfg = tmp_path / "multi.json"
    cmd = server_cmd(TOOLS)
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": cmd}, "b": {"command": cmd}}}), encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["snapshot", "--config", str(cfg)])
