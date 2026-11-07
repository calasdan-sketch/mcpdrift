"""Semantic normalization: make harmless re-serialization invisible to the diff.

A server upgrade that only reorders ``required``, an ``enum``, a ``type``
union or an ``anyOf`` list, or that re-wraps whitespace in a description, does
not change what the model sees in any way that matters. Without this, such
releases show up as drift (one of them even as a ``medium`` "type changed").

The lockfile always stores the raw surface (its digests and signature cover
exactly what the server sent). Normalization is applied to *both* sides only
when diffing. ``--strict`` turns it off.

What is deliberately NOT normalized: word content, any non-ASCII character
(so invisible or look-alike text is never "tidied away"), array order of
anything other than the four JSON-Schema set-like keywords below, and the
contents of ``default`` / ``const`` / ``examples`` (user data, not schema).
"""
from __future__ import annotations

import re
from typing import Any

from .canon import canonical_json

# Values under these keys are data, not schema: never rewrite them.
_OPAQUE = {"default", "const", "examples", "example"}
_SET_LISTS = {"anyOf", "oneOf", "allOf"}
_TEXT = {"description", "title"}

_TRAILING_WS = re.compile(r"[ \t]+(?=\n)|[ \t]+\Z")
_RUN_WS = re.compile(r"[ \t]{2,}")
_BLANKS = re.compile(r"\n{3,}")


def normalize_text(text: str) -> str:
    """ASCII-only whitespace tidy: line endings, trailing/leading blanks,
    runs of spaces/tabs. Non-ASCII characters are never touched."""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = _RUN_WS.sub(" ", t)
    t = _TRAILING_WS.sub("", t)
    t = _BLANKS.sub("\n\n", t)
    return t.strip(" \t\n")


def _sort_key(v: Any) -> str:
    try:
        return canonical_json(v)
    except (TypeError, ValueError):
        return repr(v)


def _unique_sorted(items: list) -> list:
    seen, out = set(), []
    for x in sorted(items, key=_sort_key):
        k = _sort_key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def normalize(node: Any) -> Any:
    """Return a normalized copy of a surface (or any JSON value).

    Recursive like ``canon.canonical``; a pathologically deep value raises
    ``RecursionError``, which callers treat as "compare raw" (fail closed).
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in _OPAQUE:
                out[k] = v
            elif k in _TEXT and isinstance(v, str):
                out[k] = normalize_text(v)
            elif k in ("required", "type") and isinstance(v, list) and all(isinstance(x, str) for x in v):
                out[k] = _unique_sorted(v)
            elif k == "enum" and isinstance(v, list):
                out[k] = _unique_sorted(v)
            elif k in _SET_LISTS and isinstance(v, list):
                out[k] = sorted((normalize(x) for x in v), key=_sort_key)
            else:
                out[k] = normalize(v)
        return out
    if isinstance(node, list):
        return [normalize(x) for x in node]
    return node


def safe_normalize(surface: Any) -> Any:
    try:
        return normalize(surface)
    except RecursionError:
        return surface
