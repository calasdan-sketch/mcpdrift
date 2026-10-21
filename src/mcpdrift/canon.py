"""Canonical snapshots and drift diffing for MCP server tool surfaces."""
from __future__ import annotations

import fnmatch
from typing import Any, Dict, Iterable, List, Tuple

Finding = Tuple[str, str, str]  # (kind, path, detail)


def canonical(obj: Any) -> Any:
    """Recursively sort dict keys so comparisons ignore insertion order."""
    if isinstance(obj, dict):
        return {k: canonical(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [canonical(x) for x in obj]
    return obj


def _index_by(items: Iterable[Dict[str, Any]], key: str, prefix: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            out[f"{prefix}{i}"] = canonical(item)
            continue
        name = item.get(key) or item.get("uri") or f"{prefix}{i}"
        out[str(name)] = canonical({k: v for k, v in item.items() if k != key})
    return out


def build_surface(
    init_result: Dict[str, Any] | None,
    tools: List[Dict[str, Any]],
    resources: List[Dict[str, Any]] | None = None,
    prompts: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Fold MCP initialize/tools/resources/prompt listings into one comparable surface."""
    init = init_result or {}
    return canonical(
        {
            "server": {
                "name": init.get("serverInfo", {}).get("name"),
                "version": init.get("serverInfo", {}).get("version"),
                "capabilities": init.get("capabilities", {}),
            },
            "tools": _index_by(tools, "name", "tool#"),
            "resources": _index_by(resources or [], "uri", "resource#"),
            "prompts": _index_by(prompts or [], "name", "prompt#"),
        }
    )


def brief(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def diff_surfaces(
    old: Dict[str, Any], new: Dict[str, Any], ignore: Iterable[str] = ()
) -> List[Finding]:
    """Structural diff of two canonical surfaces.

    ``ignore`` entries are glob patterns matched against the dotted path of a
    finding, e.g. ``server.version``, ``tools.search.*`` or ``prompts.*``.
    Ignoring a node hides every finding beneath it.
    """
    patterns = list(ignore)
    findings: List[Finding] = []

    def suppressed(path: str) -> bool:
        return any(
            fnmatch.fnmatchcase(path, pat) or path.startswith(pat + ".")
            for pat in patterns
        )

    def walk(o: Any, n: Any, path: List[str]) -> None:
        here = ".".join(path)
        if suppressed(here):
            return
        if isinstance(o, dict) and isinstance(n, dict):
            for k in sorted(set(o) | set(n)):
                p = path + [k]
                if k not in n:
                    if not suppressed(".".join(p)):
                        findings.append(("removed", ".".join(p), brief(o[k])))
                elif k not in o:
                    if not suppressed(".".join(p)):
                        findings.append(("added", ".".join(p), brief(n[k])))
                else:
                    walk(o[k], n[k], p)
        elif o != n:
            findings.append(("changed", here, f"{brief(o)} -> {brief(n)}"))

    walk(old, new, [])
    return findings
