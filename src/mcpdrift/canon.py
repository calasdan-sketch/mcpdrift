"""Canonical snapshots and drift diffing for MCP server tool surfaces."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from typing import Any, Dict, Iterable, List, Tuple

Finding = Tuple[str, str, str]  # (kind, path, detail)

# A raw change keeps the path as a tuple of keys (so a tool named "a.b" or a
# resource URI full of dots stays unambiguous) plus the old/new values, which
# the risk scorer and the renderers need.
RawChange = Tuple[str, Tuple[str, ...], Any, Any]  # (kind, parts, old, new)

_MISSING = object()


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
        name = str(name)
        if name in out:
            # Duplicate names are themselves suspicious (a client may pick
            # either one). Keep both, visibly, instead of silently dropping one.
            n = 2
            while f"{name}#dup{n}" in out:
                n += 1
            name = f"{name}#dup{n}"
        out[name] = canonical({k: v for k, v in item.items() if k != key})
    return out


def build_surface(
    init_result: Dict[str, Any] | None,
    tools: List[Dict[str, Any]],
    resources: List[Dict[str, Any]] | None = None,
    prompts: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Fold MCP initialize/tools/resources/prompt listings into one comparable surface."""
    init = init_result or {}
    info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
    caps = init.get("capabilities") if isinstance(init.get("capabilities"), dict) else {}
    return canonical(
        {
            "server": {
                "name": info.get("name"),
                "version": info.get("version"),
                "capabilities": caps,
            },
            "tools": _index_by(tools, "name", "tool#"),
            "resources": _index_by(resources or [], "uri", "resource#"),
            "prompts": _index_by(prompts or [], "name", "prompt#"),
        }
    )


# --------------------------------------------------------------------------
# digests


def canonical_json(obj: Any) -> str:
    """Byte-stable JSON: sorted keys, no whitespace, ASCII-escaped."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("ascii")).hexdigest()


def surface_digests(surface: Dict[str, Any]) -> Dict[str, Any]:
    """Per-entry and whole-surface SHA-256 digests.

    Per-tool digests make a lockfile diff in a pull request show exactly which
    tool moved; the whole-surface digest is what ``mcpdrift sign`` signs.
    """
    out: Dict[str, Any] = {"surface": sha256_of(surface)}
    for section in ("tools", "resources", "prompts"):
        entries = surface.get(section) or {}
        if isinstance(entries, dict):
            out[section] = {name: sha256_of(entries[name]) for name in sorted(entries)}
    return out


# --------------------------------------------------------------------------
# diffing


def brief(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def join_path(parts: Iterable[str]) -> str:
    return ".".join(parts)


def _suppressor(ignore: Iterable[str]):
    patterns = [p for p in ignore if p]

    def suppressed(path: str) -> bool:
        return any(
            fnmatch.fnmatchcase(path, pat) or path.startswith(pat + ".")
            for pat in patterns
        )

    return suppressed


def diff_raw(old: Any, new: Any, ignore: Iterable[str] = ()) -> List[RawChange]:
    """Structural diff keeping tuple paths and the old/new values."""
    suppressed = _suppressor(ignore)
    changes: List[RawChange] = []
    # Iterative walk: a hostile server cannot crash us with deep nesting.
    stack: List[Tuple[Any, Any, Tuple[str, ...]]] = [(old, new, ())]
    while stack:
        o, n, parts = stack.pop()
        if parts and suppressed(join_path(parts)):
            continue
        if isinstance(o, dict) and isinstance(n, dict):
            # push in reverse so findings come out sorted
            for k in sorted(set(o) | set(n), reverse=True):
                p = parts + (str(k),)
                if k not in n:
                    if not suppressed(join_path(p)):
                        changes.append(("removed", p, o[k], _MISSING))
                elif k not in o:
                    if not suppressed(join_path(p)):
                        changes.append(("added", p, _MISSING, n[k]))
                else:
                    stack.append((o[k], n[k], p))
        elif o != n:
            changes.append(("changed", parts, o, n))
    # Sort by path so output order is deterministic regardless of walk order.
    changes.sort(key=lambda c: c[1])
    return changes


def is_missing(value: Any) -> bool:
    return value is _MISSING


def diff_surfaces(
    old: Dict[str, Any], new: Dict[str, Any], ignore: Iterable[str] = ()
) -> List[Finding]:
    """Structural diff of two canonical surfaces.

    ``ignore`` entries are glob patterns matched against the dotted path of a
    finding, e.g. ``server.version``, ``tools.search.*`` or ``prompts.*``.
    Ignoring a node hides every finding beneath it.
    """
    findings: List[Finding] = []
    for kind, parts, o, n in diff_raw(old, new, ignore):
        here = join_path(parts)
        if kind == "removed":
            findings.append((kind, here, brief(o)))
        elif kind == "added":
            findings.append((kind, here, brief(n)))
        else:
            findings.append((kind, here, f"{brief(o)} -> {brief(n)}"))
    return findings
