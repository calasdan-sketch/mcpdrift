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


MAX_DEPTH = 400


class SurfaceError(ValueError):
    """The listing cannot be pinned safely (for example, absurd nesting)."""


def check_depth(obj: Any, limit: int = MAX_DEPTH) -> None:
    """Iterative depth guard: real schemas nest a few dozen levels at most;
    deeper input is refused instead of crashing recursive code later."""
    stack = [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if d > limit:
            raise SurfaceError(f"listing is nested more than {limit} levels deep; refusing to pin it")
        if isinstance(cur, dict):
            stack.extend((v, d + 1) for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            stack.extend((v, d + 1) for v in cur if isinstance(v, (dict, list)))


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
    templates: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Fold MCP initialize/tools/resources/prompt listings into one comparable surface.

    ``server.instructions`` (text many clients put into the model's context),
    ``serverInfo`` title/description/websiteUrl and the negotiated
    ``protocolVersion`` are pinned when the server sends them. Keys are only
    present when sent, so surfaces from older versions stay comparable.
    """
    init = init_result if isinstance(init_result, dict) else {}
    for part in (init, tools, resources, prompts, templates):
        check_depth(part)
    info: Dict[str, Any] = init["serverInfo"] if isinstance(init.get("serverInfo"), dict) else {}
    caps: Dict[str, Any] = init["capabilities"] if isinstance(init.get("capabilities"), dict) else {}
    server: Dict[str, Any] = {
        "name": info.get("name"),
        "version": info.get("version"),
        "capabilities": caps,
    }
    for k in ("title", "description", "websiteUrl"):
        if k in info:
            server[k] = info[k]
    for k in ("instructions", "protocolVersion"):
        if k in init:
            server[k] = init[k]
    surface = {
        "server": server,
        "tools": _index_by(tools, "name", "tool#"),
        "resources": _index_by(resources or [], "uri", "resource#"),
        "prompts": _index_by(prompts or [], "name", "prompt#"),
    }
    if templates:
        surface["resourceTemplates"] = _index_by(templates, "uriTemplate", "template#")
    return canonical(surface)


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
    for section in ("tools", "resources", "prompts", "resourceTemplates"):
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


def split_pattern(pattern: str) -> Tuple[str, ...]:
    """Split an ignore glob on unescaped dots; ``\\.`` is a literal dot, so
    ``tools.fs\\.read`` targets a tool literally named ``fs.read``."""
    segs, cur, i = [], [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == ".":
            cur.append(".")
            i += 2
            continue
        if ch == ".":
            segs.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    segs.append("".join(cur))
    return tuple(segs)


def _match_prefix(pat: Tuple[str, ...], parts: Tuple[str, ...]) -> bool:
    """True when ``pat`` matches ``parts`` or an ancestor of it, one path
    segment per glob segment (``*`` never crosses a segment; ``**`` matches
    any number of segments). Matching on segments, not the dot-joined
    string, means ``tools.search`` can never hide a new tool named
    ``search.exfil``."""
    if not pat:
        return True  # matched an ancestor: hides everything beneath
    head, rest = pat[0], pat[1:]
    if head == "**":
        return any(_match_prefix(rest, parts[i:]) for i in range(len(parts) + 1))
    if not parts:
        return False
    return fnmatch.fnmatchcase(parts[0], head) and _match_prefix(rest, parts[1:])


def _suppressor(ignore: Iterable[str]):
    patterns = [split_pattern(p) for p in ignore if p]

    def suppressed(parts: Tuple[str, ...]) -> bool:
        return any(_match_prefix(pat, parts) for pat in patterns)

    return suppressed


def diff_raw(old: Any, new: Any, ignore: Iterable[str] = ()) -> List[RawChange]:
    """Structural diff keeping tuple paths and the old/new values."""
    suppressed = _suppressor(ignore)
    changes: List[RawChange] = []
    # Iterative walk: a hostile server cannot crash us with deep nesting.
    stack: List[Tuple[Any, Any, Tuple[str, ...]]] = [(old, new, ())]
    while stack:
        o, n, parts = stack.pop()
        if parts and suppressed(parts):
            continue
        if isinstance(o, dict) and isinstance(n, dict):
            # push in reverse so findings come out sorted
            for k in sorted(set(o) | set(n), reverse=True):
                p = parts + (str(k),)
                if k not in n:
                    if not suppressed(p):
                        changes.append(("removed", p, o[k], _MISSING))
                elif k not in o:
                    if not suppressed(p):
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

    ``ignore`` entries are dotted glob patterns matched segment by segment,
    e.g. ``server.version``, ``tools.search.*``, ``tools.*.description`` or
    ``**.description``. Ignoring a node hides every finding beneath it.
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
