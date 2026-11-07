"""Everything between "we captured the live surface" and "here are findings":
semantic normalization, stability (cloaking) analysis, and the review token
that binds an approval to exactly the drift a human looked at."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence

from .canon import RawChange, diff_raw, is_missing, sha256_of
from .normalize import safe_normalize
from .risk import Assessed, assess_changes

_LIST_CHANGED = ("tools/list_changed", "resources/list_changed", "prompts/list_changed")


@dataclass
class Prepared:
    items: List[Assessed]
    raw: List[RawChange]
    unstable: bool = False
    cosmetic_ignored: int = 0
    token: str = ""
    notes: List[str] = field(default_factory=list)


def _jsonable(v: Any) -> Any:
    return "\x00missing" if is_missing(v) else v


def review_token(raw: Sequence[RawChange], extra: Iterable[str] = ()) -> str:
    """16 hex chars identifying exactly this set of changes (old and new
    values included). If the server changes again after a human reviewed the
    drift, the token no longer matches and the approval is refused."""
    payload = [[k, list(p), _jsonable(o), _jsonable(n)] for k, p, o, n in raw]
    return sha256_of({"changes": payload, "extra": sorted(extra)})[:16]


def stability_items(samples: Sequence[Dict[str, Any]], strict: bool = False,
                    ignore: Sequence[str] = ()) -> List[Assessed]:
    """Compare later listings in one session with the first. A server that
    answers differently within seconds is cloaking or counting calls."""
    out: List[Assessed] = []
    if len(samples) < 2:
        return out
    norm = (lambda s: s) if strict else safe_normalize
    base = norm(samples[0])
    seen = set()
    for k, later in enumerate(samples[1:], start=2):
        cur = norm(later)
        raw = diff_raw(base, cur, ignore=ignore)
        if not raw:
            continue
        key = sha256_of([[c[0], list(c[1]), _jsonable(c[2]), _jsonable(c[3])] for c in raw])
        if key in seen:
            continue
        seen.add(key)
        for a in assess_changes(raw, base, cur):
            a.parts = ("unstable", f"listing{k}") + tuple(a.parts)
            a.path = ".".join(a.parts)
            a.bump("high", f"server answered differently on listing #{k} than on listing #1 in the same session "
                           "(call-count or cloaking behaviour)", "unstable")
            out.append(a)
    return out


def dynamic_items(notifications: Iterable[str]) -> List[Assessed]:
    out = []
    for m in sorted(set(notifications)):
        short = m.replace("notifications/", "")
        if short in _LIST_CHANGED:
            a = Assessed("changed", f"server.dynamic.{short}", ("server", "dynamic", short),
                         f"server sent notifications/{short}", "low")
            a.bump("low", "server announced that its listing changes at runtime; a lock pins one moment of a "
                          "dynamic surface", "dynamic")
            out.append(a)
    return out


def prepare(old: Dict[str, Any], samples: Sequence[Dict[str, Any]], notifications: Iterable[str] = (),
            ignore: Sequence[str] = (), strict: bool = False) -> Prepared:
    """Diff the lock against the live surface and add stability findings."""
    live = samples[0]
    if strict:
        o, n = old, live
        raw = diff_raw(o, n, ignore=ignore)
        cosmetic = 0
    else:
        o, n = safe_normalize(old), safe_normalize(live)
        raw = diff_raw(o, n, ignore=ignore)
        cosmetic = max(0, len(diff_raw(old, live, ignore=ignore)) - len(raw))
    items = assess_changes(raw, o, n)
    unst = stability_items(samples, strict, ignore)
    dyn = dynamic_items(notifications)
    items = items + unst + dyn
    token = review_token(raw, [i.path + ":" + i.severity for i in unst + dyn])
    return Prepared(items, raw, bool(unst), cosmetic, token)
