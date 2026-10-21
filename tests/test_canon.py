"""Tests for canonical surfaces and drift diffing."""
from mcpdrift.canon import build_surface, diff_surfaces


def surface(tools, version="1.0.0", resources=None, prompts=None):
    init = {"serverInfo": {"name": "demo", "version": version}, "capabilities": {"tools": {}}}
    return build_surface(init, tools, resources, prompts)


BASE = [
    {"name": "search", "description": "search things", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "read", "description": "read a doc", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
]


def test_key_order_is_irrelevant():
    a = surface([dict(BASE[0]), dict(BASE[1])])
    b = surface([dict(reversed(list(BASE[1].items()))), dict(reversed(list(BASE[0].items())))])
    assert diff_surfaces(a, b) == []


def test_added_and_removed_tools():
    old = surface([BASE[0]])
    new = surface([BASE[0], BASE[1]])
    findings = diff_surfaces(old, new)
    assert ("added", "tools.read", "{'description': 'read a doc', ...") in [
        (k, p, d[:31] + "...") for k, p, d in findings
    ] or any(k == "added" and p == "tools.read" for k, p, d in findings)
    gone = diff_surfaces(new, old)
    assert any(k == "removed" and p == "tools.read" for k, p, d in gone)


def test_schema_change_is_drift():
    old = surface([BASE[0]])
    changed = [dict(BASE[0])]
    changed[0]["inputSchema"] = {"type": "object", "properties": {"q": {"type": "integer"}}}
    findings = diff_surfaces(old, surface(changed))
    assert any(k == "changed" and "inputSchema" in p for k, p, d in findings)


def test_description_change_is_drift():
    old = surface([BASE[0]])
    changed = [dict(BASE[0], description="renamed")]
    findings = diff_surfaces(old, surface(changed))
    assert findings == [("changed", "tools.search.description", "'search things' -> 'renamed'")]


def test_server_version_change_reports_path():
    findings = diff_surfaces(surface([BASE[0]], version="1.0.0"), surface([BASE[0]], version="2.0.0"))
    assert findings == [("changed", "server.version", "'1.0.0' -> '2.0.0'")]


def test_ignore_hides_node_and_children():
    old = surface([BASE[0]], version="1.0.0")
    new = surface([BASE[0]], version="2.0.0")
    assert diff_surfaces(old, new, ignore=["server.version"]) == []
    assert diff_surfaces(old, new, ignore=["server.*"]) == []


def test_resources_and_prompts_indexed():
    old = surface([], resources=[{"uri": "file:///a", "name": "A"}], prompts=[{"name": "p1"}])
    new = surface([], resources=[{"uri": "file:///a", "name": "A"}], prompts=[{"name": "p1", "description": "d"}])
    findings = diff_surfaces(old, new)
    assert any(k == "added" and p.startswith("prompts.p1") for k, p, d in findings)


def test_nested_capability_change():
    old = surface([BASE[0]])
    changed = [dict(BASE[0])]
    init_caps = {"tools": {"listChanged": False}}
    a = build_surface({"serverInfo": {"name": "d", "version": "1"}, "capabilities": init_caps}, [BASE[0]])
    b = build_surface({"serverInfo": {"name": "d", "version": "1"}, "capabilities": {"tools": {"listChanged": True}}}, [BASE[0]])
    findings = diff_surfaces(a, b)
    assert findings == [("changed", "server.capabilities.tools.listChanged", "False -> True")]
