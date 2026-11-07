"""Human- and machine-readable renderings of assessed drift."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import posixpath
import re
import secrets
from typing import Any, Dict, List, Optional, Sequence

from .risk import Assessed, max_severity

_TOKEN = re.compile(r"\s+|\w+|[^\w\s]", re.UNICODE)
MAX_DIFF_TOKENS = 20_000


def _visible(text: str) -> str:
    """Make invisible / control characters visible as \\uXXXX escapes."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in "\n\t" or (0x20 <= cp < 0x7F):
            out.append(ch)
        elif cp < 0x20 or 0x7F <= cp < 0xA0 or ch in "­͏؜᠎ㅤ﻿" or (
            0x200B <= cp <= 0x200F or 0x202A <= cp <= 0x202E or 0x2060 <= cp <= 0x206F
            or 0xFE00 <= cp <= 0xFE0F or 0xE0000 <= cp <= 0xE007F
        ):
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _oneline(text: str) -> str:
    """Visible and single-line: names/paths/reasons must never break a line."""
    return _visible(text).replace("\n", "\\n").replace("\t", "\\t")


def word_diff(old: str, new: str) -> str:
    """Inline word diff: ``[-removed-]{+added+}``; invisible characters escaped."""
    a = _TOKEN.findall(_visible(old))[:MAX_DIFF_TOKENS]
    b = _TOKEN.findall(_visible(new))[:MAX_DIFF_TOKENS]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    out: List[str] = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            out.append("".join(a[i1:i2]))
        else:
            if i2 > i1:
                out.append("[-" + "".join(a[i1:i2]) + "-]")
            if j2 > j1:
                out.append("{+" + "".join(b[j1:j2]) + "+}")
    return "".join(out)


def _text_diff(a: Assessed) -> Optional[str]:
    if a.kind == "changed" and isinstance(a.old, str) and isinstance(a.new, str):
        return word_diff(a.old, a.new)
    return None


_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted(items: Sequence[Assessed]) -> List[Assessed]:
    return sorted(items, key=lambda a: (_ORDER[a.severity], a.parts))


def summary_counts(items: Sequence[Assessed]) -> Dict[str, int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for a in items:
        counts[a.severity] += 1
    return counts


def _counts_line(items: Sequence[Assessed]) -> str:
    c = summary_counts(items)
    return ", ".join(f"{n} {s}" for s, n in c.items() if n)


def render_text(items: Sequence[Assessed], color: bool = False, noun: str = "drift finding(s)") -> str:
    if not items:
        return "no drift\n"
    colors = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
    reset = "\033[0m" if color else ""
    lines = []
    for a in _sorted(items):
        tag = a.severity.upper()
        if color:
            tag = colors[a.severity] + tag + reset
        lines.append(f"{tag:<{8 + (len(colors[a.severity]) + len(reset) if color else 0)}} {a.kind:7} {_oneline(a.path)}")
        for r in a.reasons:
            lines.append(f"           - {_oneline(r)}")
        diff = _text_diff(a)
        if diff is not None:
            lines.append("           " + diff.replace("\n", "\n           "))
        else:
            lines.append("           " + _oneline(a.detail))
    lines.append("")
    lines.append(f"{len(items)} {noun}: {_counts_line(items)}")
    return "\n".join(lines) + "\n"


def _md_escape(text: str) -> str:
    text = _visible(text)
    for ch in "\\`*_[]|#!~":
        text = text.replace(ch, "\\" + ch)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")
    # Stop GitHub auto-linking attacker-chosen URLs / emails / mentions.
    text = re.sub(r"(?i)(https?|ftp|wss?|file)://", lambda m: m.group(1) + ":&#8203;//", text)
    text = re.sub(r"(?i)www\.", "www&#8203;.", text)
    return text.replace("@", "@&#8203;")


def render_markdown(items: Sequence[Assessed], title: str = "mcpdrift", noun: str = "drift finding(s)",
                    empty: str = "no drift\n\nThe live MCP surface matches the lockfile.") -> str:
    title = _md_escape(title)
    if not items:
        return f"### {title}: {empty}\n"
    worst = max_severity(a.severity for a in items)
    icon = {"critical": "STOP", "high": "WARN", "medium": "CHECK", "low": "NOTE", "info": "NOTE"}[worst or "info"]
    out = [f"### {title}: {len(items)} {noun} [{icon}]", "", f"Highest severity: **{worst}** ({_counts_line(items)})", ""]
    out.append("| Severity | Change | Path | Why |")
    out.append("|---|---|---|---|")
    for a in _sorted(items):
        why = "; ".join(a.reasons) or "-"
        out.append(f"| {a.severity} | {a.kind} | {_md_escape(a.path)} | {_md_escape(why)} |")
    diffs = [(a, _text_diff(a)) for a in _sorted(items) if a.parts and a.parts[-1] in ("description", "title")]
    diffs = [(a, d) for a, d in diffs if d is not None]
    if diffs:
        out += ["", "<details><summary>Text changes (word diff)</summary>", ""]
        for a, _d in diffs:
            body = (f"- {_visible(a.old)}".replace("\n", "\n- ") + "\n"
                    + f"+ {_visible(a.new)}".replace("\n", "\n+ "))
            # Fence longer than any backtick run inside, so hostile text
            # cannot close the block and inject markdown into the summary.
            runs = [len(m) for m in re.findall(r"`+", body)]
            fence = "`" * max(3, (max(runs) + 1) if runs else 3)
            out.append(f"**{_md_escape(a.path)}**")
            out.append("")
            out.append(fence + "diff")
            out.append(body)
            out.append(fence)
            out.append("")
        out.append("</details>")
    out.append("")
    out.append("Accept intended changes by re-running `mcpdrift snapshot` and committing the lockfile.")
    return "\n".join(out) + "\n"


def _gh_escape(text: str) -> str:
    return _visible(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_prop(text: str) -> str:
    return _gh_escape(text).replace(":", "%3A").replace(",", "%2C")


def stop_commands(text: str) -> str:
    """Wrap untrusted text so the GitHub runner will not execute any
    ``::command::`` lines inside it (``::stop-commands::`` with a random,
    unguessable resume token)."""
    token = secrets.token_hex(16)
    return f"::stop-commands::{token}\n{text}{'' if text.endswith(chr(10)) else chr(10)}::{token}::\n"


def render_github(items: Sequence[Assessed], lock_path: str = "") -> str:
    """GitHub Actions workflow commands: one annotation per finding."""
    lines = []
    for a in _sorted(items):
        level = "error" if a.severity in ("critical", "high") else "warning" if a.severity == "medium" else "notice"
        msg = f"{a.kind} {a.path}: " + ("; ".join(a.reasons) or a.detail)
        props = f"title={_gh_prop('mcpdrift ' + a.severity)}"
        if lock_path:
            props = f"file={_gh_prop(lock_path)}," + props
        lines.append(f"::{level} {props}::{_gh_escape(msg)}")
    return "\n".join(lines) + ("\n" if lines else "")


def _jsonable(v: Any) -> Any:
    try:
        json.dumps(v)
        return v
    except (TypeError, ValueError):
        return repr(v)


def render_json(items: Sequence[Assessed], extra: Optional[Dict[str, Any]] = None) -> str:
    payload: Dict[str, Any] = {
        "drift": bool(items),
        "max_severity": max_severity(a.severity for a in items),
        "counts": summary_counts(items),
        "findings": [],
    }
    for a in items:
        d = a.as_dict()
        d["old"] = _jsonable(a.old)
        d["new"] = _jsonable(a.new)
        diff = _text_diff(a)
        if diff is not None:
            d["word_diff"] = diff
        payload["findings"].append(d)
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


# --------------------------------------------------------------------------
# SARIF 2.1.0 (GitHub code scanning, GitLab, Azure DevOps, VS Code viewers)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}

SARIF_RULES = [
    ("MCPD001", "security-signal", "Text or metadata matches a known tool-poisoning or rug-pull signal"),
    ("MCPD002", "description-changed", "A description or title the model reads was changed"),
    ("MCPD003", "breaking-schema-change", "A tool's input contract changed in a way that breaks existing calls"),
    ("MCPD004", "widened-schema", "A tool's input contract was widened"),
    ("MCPD005", "entry-added", "A new tool, resource or prompt is now exposed to the agent"),
    ("MCPD006", "entry-removed", "A tool, resource or prompt was removed"),
    ("MCPD007", "unstable-listing", "The server answered differently within one session"),
    ("MCPD008", "dynamic-surface", "The server announced runtime changes to its listing"),
    ("MCPD009", "other-drift", "Other drift from the locked surface"),
]
_RULE_INDEX = {r[0]: i for i, r in enumerate(SARIF_RULES)}


def _rule_id(a: Assessed) -> str:
    tags = set(a.tags)
    if "unstable" in tags:
        return "MCPD007"
    if "dynamic" in tags:
        return "MCPD008"
    if "security" in tags:
        return "MCPD001"
    if "breaking" in tags and a.kind != "removed":
        return "MCPD003"
    if "text" in tags:
        return "MCPD002"
    if "added" in tags:
        return "MCPD005"
    if "widened" in tags:
        return "MCPD004"
    if a.kind == "removed" or "breaking" in tags:
        return "MCPD006"
    return "MCPD009"


def locate_line(lock_text: str, parts: Sequence[str]) -> int:
    """Best-effort 1-based line in the lockfile where this entry lives."""
    if not lock_text or len(parts) < 2 or parts[0] == "unstable":
        return 1
    section, name = parts[0], parts[1]
    lines = lock_text.split("\n")
    start = 0
    for i, ln in enumerate(lines):
        if ln.startswith("    " + json.dumps(section) + ": {"):
            start = i
            break
    needle = "      " + json.dumps(name, ensure_ascii=True) + ": "
    for i in range(start, len(lines)):
        if lines[i].startswith(needle):
            return i + 1
    return 1


def _sarif_uri(path: str) -> str:
    if os.path.isabs(path):  # inside the working folder: keep the relative path code scanning needs
        try:
            rel = os.path.relpath(path)
            if not rel.startswith("..") and not os.path.isabs(rel):
                path = rel
        except ValueError:  # other drive on Windows
            pass
    p = path.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p) or ".." in p.split("/"):
        return posixpath.basename(p) or "mcp.lock.json"
    return posixpath.normpath(p) if p else "mcp.lock.json"


def render_sarif(items: Sequence[Assessed], lock_path: str = "", lock_text: str = "",
                 tool_version: str = "") -> str:
    """SARIF 2.1.0 log with one result per finding. Text from the server is
    escaped (control and invisible characters shown as \\uXXXX)."""
    uri = _sarif_uri(lock_path or "mcp.lock.json")
    rules = [
        {"id": rid, "name": name, "shortDescription": {"text": desc},
         "defaultConfiguration": {"level": "warning"}}
        for rid, name, desc in SARIF_RULES
    ]
    results = []
    for a in _sorted(items):
        rid = _rule_id(a)
        msg = f"{a.severity.upper()} {a.kind} {_oneline(a.path)}: " + "; ".join(_oneline(r) for r in a.reasons)
        fp = hashlib.sha256(f"{rid}|{a.kind}|{a.path}|{a.detail}".encode("utf-8", "replace")).hexdigest()
        results.append({
            "ruleId": rid,
            "ruleIndex": _RULE_INDEX[rid],
            "level": _SARIF_LEVEL[a.severity],
            "message": {"text": msg.strip().rstrip(":")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": locate_line(lock_text, a.parts)},
            }}],
            "partialFingerprints": {"mcpdrift/v1": fp},
            "properties": {"severity": a.severity, "security-severity": _SARIF_SCORE[a.severity],
                           "tags": list(a.tags)},
        })
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcpdrift", "version": tool_version or "0",
                                "informationUri": "https://github.com/calasdan-sketch/mcpdrift",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(log, indent=2) + "\n"
