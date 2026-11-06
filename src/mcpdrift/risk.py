"""Severity scoring for drift findings, with a rug-pull lens on text changes.

Every structural change gets a severity (info < low < medium < high <
critical) and one or more human reasons. Text that the model reads (tool,
property, prompt and resource descriptions and titles) is checked for
signals typical of tool-poisoning: invisible characters, mixed-script
homoglyphs, hidden-instruction markers, secret-file paths, exfiltration
wording and URLs. Only signals that are *new* in the changed text count, so a
long-standing phrase does not re-alert on every release.

This is a heuristic, deterministic, offline scorer. It raises the alarm on the
patterns published attacks use; it cannot prove a description is benign.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .canon import RawChange, brief, is_missing, join_path

SEVERITIES = ("info", "low", "medium", "high", "critical")
_STRONG_KINDS = {
    "instruction aimed at the model",
    "mentions secret files or keys",
    "exfiltration-style wording",
    "contains zero-width / invisible characters",
    "mixed-script look-alike word(s)",
    "contains unusual Unicode variation selectors (can hide data)",
    "look-alike word(s) in a non-Latin script",
    "contains an HTML comment (hidden from rendered views, read by the model)",
    "base64-encoded text",
    "contains control characters (can forge log or CI output)",
}
_NAME_KINDS = {
    "contains control characters (can forge log or CI output)",
    "look-alike word(s) in a non-Latin script",
    "contains invisible Unicode tag characters (can smuggle hidden instructions)",
    "contains bidirectional control characters (text can display differently than it reads)",
    "contains zero-width / invisible characters",
    "contains unusual Unicode variation selectors (can hide data)",
    "mixed-script look-alike word(s)",
}


def name_signals(name: str) -> List[Tuple[str, str]]:
    """Look-alike / invisible-character checks for a tool or prompt *name*
    (a name like ``read_f\u0456le`` can shadow ``read_file``)."""
    out = [(s, "name " + r) for s, r in text_signals(name.replace("_", " ").replace("-", " ") + " " + name)
           if r.split(":")[0] in _NAME_KINDS]
    if any(c in name for c in "\r\n\t") and not any("control" in r for _, r in out):
        out.append(("high", "name contains control characters (can forge log or CI output)"))
    return out
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

TEXT_KEYS = {"description", "title"}
SECTIONS = ("tools", "resources", "prompts")

# Hard caps so a hostile server cannot make the scorer slow.
MAX_TEXT = 200_000


def rank(sev: str) -> int:
    return _RANK[sev]


def max_severity(sevs: Iterable[str]) -> Optional[str]:
    best = None
    for s in sevs:
        if best is None or _RANK[s] > _RANK[best]:
            best = s
    return best


@dataclass
class Assessed:
    kind: str  # added | removed | changed
    path: str
    parts: Tuple[str, ...]
    detail: str
    severity: str
    reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)  # e.g. breaking, widened, security
    old: Any = None
    new: Any = None

    def bump(self, sev: str, reason: str, tag: Optional[str] = None) -> None:
        if _RANK[sev] > _RANK[self.severity]:
            self.severity = sev
        if reason not in self.reasons:
            self.reasons.append(reason)
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def finish(self) -> "Assessed":
        """Several independent strong signals together are the signature of a
        poisoned description, not an accident: escalate to critical."""
        strong = [r for r in self.reasons
                  if r.replace("inside base64 - ", "").replace("argument ", "").split(":")[0] in _STRONG_KINDS]
        if len(strong) >= 2:
            self.bump("critical", f"{len(strong)} independent poisoning signals together", "security")
        return self

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "detail": self.detail,
            "severity": self.severity,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
        }


# --------------------------------------------------------------------------
# text signals

# Invisible / format characters. ZWJ (U+200D) and the emoji variation
# selectors are handled separately below, because legitimate emoji use them.
_INVISIBLE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200e\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u206f\u3164\ufeff\uffa0"
    "\U000e0000-\U000e007f]"
)
# ZWJ glued to a letter or digit is splitting a word, not joining emoji.
_ZWJ_IN_WORD = re.compile("[\\w]\u200d|\u200d[\\w]")
# Runs of variation selectors can encode hidden bytes ("emoji smuggling");
# a single VS15/VS16 after an emoji is normal.
_VS_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}|[\ufe00-\ufe0d\U000e0100-\U000e01ef]")
_STRIP = re.compile(_INVISIBLE.pattern[:-1] + "\u200d\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_TAGS_BLOCK = re.compile("[\U000e0000-\U000e007f]")

_INSTRUCTION = re.compile(
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|critical|note_to_ai|ai)\b[^>]{0,40}>"
    r"|\[\s*(system|important|critical|admin)\s*\]"
    r"|\*\*\s*system\s*\*\*"
    r"|\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|other)\s+(instructions|rules|directions)"
    r"|\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|notify|alert)\s+(this\s+to\s+)?(the\s+)?user"
    r"|\bwithout\s+(telling|informing|notifying|asking)\s+(the\s+)?user",
    re.IGNORECASE,
)
# Weaker phrasing that legitimate docs also use; worth a look, not an alarm.
_INSTRUCTION_WEAK = re.compile(
    r"\b(before|prior\s+to)\s+(using|calling|invoking)\s+(this|any|the)\s+tool"
    r"|\bthis\s+is\s+(very\s+|extremely\s+)?important\b",
    re.IGNORECASE,
)

_SENSITIVE_PATH = re.compile(
    r"[/\\]?\.(ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials)\b"
    r"|\bid_(rsa|ed25519|ecdsa|dsa)\b"
    r"|(^|[\s/\\'\"`(])\.env\b"
    r"|/etc/(passwd|shadow|sudoers)"
    r"|\b(mcp|claude_desktop_config)\.json\b"
    r"|\bprivate[\s_-]?key\b"
    r"|\bseed\s+phrase\b|\bwallet\.dat\b",
    re.IGNORECASE,
)
# Generic secret words: normal in a GitHub or auth tool, notable when new.
_SENSITIVE_WORD = re.compile(
    r"\b(api|access|secret|auth|bearer|session|refresh)[\s_-]?(key|token)s?\b"
    r"|\b(password|passwd|credentials?|mnemonic|keychain)\b",
    re.IGNORECASE,
)

_EXFIL = re.compile(
    # verb ... to/into/via <external destination>
    r"\b(send|post|upload|forward|transmit|exfiltrate|leak|copy|include|pass|append|attach|embed)\b"
    r"[^.\n]{0,80}\b(to|into|via)\b\s+(the\s+|an?\s+|this\s+)?"
    r"(https?://|webhook\b|external\s+(server|endpoint|url)\b|[\w.+-]+@[\w-]+\.[a-z]{2,})"
    # ... or smuggled through a side-channel argument
    r"|\b(send|pass|include|put|append|attach|embed|copy)\b[^.\n]{0,80}\b(as|in|into)\b[^.\n]{0,30}\bsidenote\b",
    re.IGNORECASE,
)
_HTML_COMMENT = re.compile(r"<!--")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
# single letters split by separators: I-M-P-O-R-T-A-N-T, i.g.n.o.r.e
_SPLIT_LETTERS = re.compile(r"\b(?:\w[\s\-_.*|/]){3,}\w\b")
# Cyrillic/Greek letters that look like Latin ones.
_CONFUSABLE = set("аеорсухіјѕһԁԛԝвкмнтАВЕКМНОРСТХІЈЅԜοαιντυκρΑΒΕΖΗΙΚΜΝΟΡΤΥΧ")
URL_KEYS = {"uri", "uriTemplate", "$schema", "$id", "$ref", "url", "href", "icons", "src"}
STRUCTURAL_KEYS = {"type", "$schema", "$id", "$ref", "format", "mimeType"}

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>)]{1,300}", re.IGNORECASE)

_SENSITIVE_NAME = re.compile(
    r"(ssh|id_rsa|private_?key|password|passwd|secret|token|credential|api_?key|cookie|"
    r"session|mnemonic|seed|wallet|env(iron)?|keychain|authorization)",
    re.IGNORECASE,
)

_SCRIPT_PREFIXES = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def _scripts_in(word: str) -> set:
    found = set()
    for ch in word:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            for p in _SCRIPT_PREFIXES:
                if name.startswith(p):
                    found.add(p)
                    break
    return found


def _mixed_script_words(text: str) -> List[str]:
    out = []
    for word in re.findall(r"\w{4,}", text):
        # 4+ letters: skips unit symbols like "kΩ" or "μs"
        if sum(ch.isalpha() for ch in word) >= 4 and len(_scripts_in(word)) > 1:
            out.append(word)
            if len(out) >= 5:
                break
    return out


def _confusable_words(text: str) -> List[str]:
    """Words written entirely in Cyrillic/Greek look-alikes inside Latin text
    (e.g. "\u0440\u0430\u0443" for "pay")."""
    if sum(c.isascii() and c.isalpha() for c in text) < 3:
        return []  # genuinely non-Latin text
    out = []
    for word in re.findall(r"\w{2,}", text):
        if all(c in _CONFUSABLE for c in word):
            out.append(word)
            if len(out) >= 3:
                break
    return out


def _deobfuscate(norm: str) -> str:
    def join(m: "re.Match[str]") -> str:
        return re.sub(r"[\s\-_.*|/]", "", m.group(0))
    return _SPLIT_LETTERS.sub(join, norm).lower().translate(_LEET)


def _b64_text(blob: str) -> Optional[str]:
    import base64
    import binascii
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        dec = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c in "\n\t" for c in dec)
    return dec if dec and printable / len(dec) > 0.95 else None


def _normalize(text: str) -> str:
    # NFKC folds compatibility look-alikes (fullwidth, ligatures); stripping
    # invisibles defeats "<IMP​ORTANT>"-style splitting.
    return _STRIP.sub("", unicodedata.normalize("NFKC", text))


def text_signals(text: str, other_names: Sequence[str] = (), allow_urls: bool = False,
                 _depth: int = 0) -> List[Tuple[str, str]]:
    """Return (severity, reason) pairs for risky content in ``text``.

    Text longer than ``MAX_TEXT`` is itself flagged and its head and tail are
    scanned, so padding cannot push a payload out of view.
    """
    if not isinstance(text, str) or not text:
        return []
    out: List[Tuple[str, str]] = []
    if len(text) > MAX_TEXT:
        out.append(("high", f"text is {len(text)} characters (over {MAX_TEXT}); only head and tail were scanned"))
        half = MAX_TEXT // 2
        text = text[:half] + "\n" + text[-half:]
    if _CONTROL.search(text):
        out.append(("high", "contains control characters (can forge log or CI output)"))
    if _TAGS_BLOCK.search(text):
        out.append(("critical", "contains invisible Unicode tag characters (can smuggle hidden instructions)"))
    elif _BIDI.search(text):
        out.append(("critical", "contains bidirectional control characters (text can display differently than it reads)"))
    elif _INVISIBLE.search(text) or _ZWJ_IN_WORD.search(text):
        out.append(("high", "contains zero-width / invisible characters"))
    if _VS_RUN.search(text):
        out.append(("high", "contains unusual Unicode variation selectors (can hide data)"))
    mixed = _mixed_script_words(text)
    if mixed:
        out.append(("high", "mixed-script look-alike word(s): " + ", ".join(repr(w) for w in mixed[:3])))
    conf = _confusable_words(text)
    if conf:
        out.append(("high", "look-alike word(s) in a non-Latin script: " + ", ".join(repr(w) for w in conf)))
    norm = _normalize(text)
    m = _INSTRUCTION.search(norm)
    if m:
        out.append(("high", f"instruction aimed at the model: {m.group(0)[:60]!r}"))
    else:
        m = _INSTRUCTION.search(_deobfuscate(norm))
        if m:
            out.append(("high", f"instruction aimed at the model: obfuscated {m.group(0)[:60]!r}"))
    if _HTML_COMMENT.search(norm):
        out.append(("high", "contains an HTML comment (hidden from rendered views, read by the model)"))
    for blob in _BASE64.findall(norm)[:5]:
        if not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob) and re.search(r"[0-9+/]", blob)):
            continue
        dec = _b64_text(blob)
        if dec is not None:
            out.append(("high", f"base64-encoded text: {dec[:40]!r}"))
            if _depth == 0:
                for sev, reason in text_signals(dec, other_names, allow_urls, _depth=1):
                    out.append((sev, "inside base64 - " + reason))
        else:
            out.append(("medium", "long encoded-looking blob (base64?)"))
        break
    m = _INSTRUCTION_WEAK.search(norm)
    if m:
        out.append(("medium", f"imperative aimed at the model: {m.group(0)[:60]!r}"))
    m = _SENSITIVE_PATH.search(norm)
    if m:
        out.append(("high", f"mentions secret files or keys: {m.group(0).strip()[:40]!r}"))
    m = _SENSITIVE_WORD.search(norm)
    if m:
        out.append(("medium", f"mentions credentials: {m.group(0).strip()[:40]!r}"))
    m = _EXFIL.search(norm)
    if m:
        out.append(("high", f"exfiltration-style wording: {m.group(0)[:60]!r}"))
    urls = [] if allow_urls else _URL.findall(norm)
    if urls:
        out.append(("medium", "contains URL(s): " + ", ".join(u[:60] for u in urls[:3])))
    low = norm.lower()
    for name in other_names:
        if len(name) >= 4 and re.search(r"(?<![\w-])" + re.escape(name.lower()) + r"(?![\w-])", low):
            out.append(("medium", f"refers to another tool: {name!r} (cross-tool steering)"))
            break
    return out


def _new_signals(old_text: Any, new_text: Any, names: Sequence[str], allow_urls: bool = False) -> List[Tuple[str, str]]:
    old = {r for _, r in text_signals(old_text, names, allow_urls)} if isinstance(old_text, str) else set()
    # Compare on the signal *kind* (text before ':') so a URL that merely
    # changes is still new, but the same category of phrase that was already
    # there does not re-alert.
    old_kinds = {r.split(":")[0] for r in old}
    out = []
    for sev, reason in text_signals(new_text, names, allow_urls):
        if reason in old:
            continue
        if reason.split(":")[0] in old_kinds and sev != "critical":
            # same category existed before; still worth a look, one level down
            sev = SEVERITIES[max(1, _RANK[sev] - 1)]
        out.append((sev, reason))
    return out


# --------------------------------------------------------------------------
# walking helpers


def iter_texts(node: Any, parts: Tuple[str, ...] = ()) -> Iterable[Tuple[Tuple[str, ...], str]]:
    """Yield (path, text) for every string value under ``node`` that the
    model may read: descriptions and titles, but also defaults, enums,
    consts, examples and unknown fields. Purely structural keys are skipped."""
    if isinstance(node, str):
        yield parts, node
        return
    stack = [(node, parts)]
    while stack:
        cur, p = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, str):
                    if k not in STRUCTURAL_KEYS:
                        yield p + (str(k),), v
                elif isinstance(v, (dict, list)):
                    stack.append((v, p + (str(k),)))
        elif isinstance(cur, list):
            for i, v in enumerate(cur):
                if isinstance(v, str):
                    yield p + (str(i),), v
                elif isinstance(v, (dict, list)):
                    stack.append((v, p + (str(i),)))


def _url_ok(parts: Tuple[str, ...]) -> bool:
    return any(x in URL_KEYS for x in parts[-2:])


def _signals_at(parts: Tuple[str, ...], text: str, names: Sequence[str]) -> List[Tuple[str, str]]:
    return text_signals(text, names, allow_urls=_url_ok(parts))


def iter_property_names(schema: Any, parts: Tuple[str, ...] = ()) -> Iterable[Tuple[Tuple[str, ...], str]]:
    stack = [(schema, parts)]
    while stack:
        cur, p = stack.pop()
        if isinstance(cur, dict):
            props = cur.get("properties")
            if isinstance(props, dict):
                for name in props:
                    yield p + ("properties", str(name)), str(name)
            for k, v in cur.items():
                if isinstance(v, (dict, list)):
                    stack.append((v, p + (str(k),)))
        elif isinstance(cur, list):
            for i, v in enumerate(cur):
                if isinstance(v, (dict, list)):
                    stack.append((v, p + (str(i),)))


def _get(surface: Dict[str, Any], parts: Sequence[str]) -> Any:
    cur: Any = surface
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        else:
            return None
    return cur


def _all_names(*surfaces: Dict[str, Any]) -> List[str]:
    names = set()
    for s in surfaces:
        for sec in ("tools", "prompts"):
            entries = s.get(sec) if isinstance(s, dict) else None
            if isinstance(entries, dict):
                names.update(entries)
    return sorted(names)


def _owner(parts: Tuple[str, ...]) -> Optional[str]:
    if len(parts) >= 2 and parts[0] in SECTIONS:
        return parts[1]
    return None


# --------------------------------------------------------------------------
# assessment


def _assess_entry_added(a: Assessed, entry: Any, names: Sequence[str]) -> None:
    section = a.parts[0]
    others = [n for n in names if n != a.parts[1]]
    a.bump("medium" if section == "tools" else "low",
           f"new {section[:-1]} the agent can now see/use", "added")
    for sev, reason in name_signals(a.parts[1]):
        a.bump(sev, reason, "security")
    if isinstance(entry, dict):
        ann = entry.get("annotations")
        if isinstance(ann, dict) and ann.get("destructiveHint") is True and ann.get("readOnlyHint") is not True:
            a.bump("high", "new tool declares destructiveHint=true", "security")
        for tp, text in iter_texts(entry, a.parts):
            for sev, reason in _signals_at(tp, text, others):
                a.bump(sev, reason, "security")
        for _, pname in iter_property_names(entry.get("inputSchema")):
            if _SENSITIVE_NAME.search(pname):
                a.bump("high", f"asks for a sensitive-looking argument: {pname!r}", "security")
                break


def _schema_context(parts: Tuple[str, ...]) -> Optional[int]:
    """Index of the 'inputSchema'/'outputSchema'/'arguments' segment, if any."""
    for i, p in enumerate(parts):
        if p in ("inputSchema", "outputSchema", "arguments") and i >= 2:
            return i
    return None


def _assess_schema(a: Assessed, old_s: Dict[str, Any], new_s: Dict[str, Any]) -> None:
    parts = a.parts
    i = _schema_context(parts)
    if i is None:
        return
    which = parts[i]
    is_output = which == "outputSchema"
    last = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else ""

    if which == "arguments":  # prompt arguments: list of {name, required}
        a.bump("low", "prompt arguments changed")
        return

    # property added / removed
    if parent == "properties" and a.kind in ("added", "removed"):
        if a.kind == "added":
            req = _get(new_s, parts[:-2] + ("required",))
            if isinstance(req, list) and last in req and not is_output:
                a.bump("medium", f"new required argument {last!r} (existing calls will fail)", "breaking")
            else:
                a.bump("low", f"new optional {'output field' if is_output else 'argument'} {last!r}", "widened")
            if _SENSITIVE_NAME.search(last) and not is_output:
                a.bump("high", f"new argument has a sensitive-looking name: {last!r}", "security")
        else:
            a.bump("medium", f"{'output field' if is_output else 'argument'} {last!r} removed", "breaking")
        return

    if last == "required":
        o = set(a.old) if isinstance(a.old, list) else set()
        n = set(a.new) if isinstance(a.new, list) else set()
        if is_output:
            a.bump("low", "output required fields changed")
        elif n - o:
            a.bump("medium", "argument(s) became required: " + ", ".join(sorted(map(str, n - o))), "breaking")
        else:
            a.bump("low", "argument(s) no longer required: " + ", ".join(sorted(map(str, o - n))), "widened")
        return

    if last == "enum":
        o = a.old if isinstance(a.old, list) else []
        n = a.new if isinstance(a.new, list) else []
        gone = [x for x in o if x not in n]
        new = [x for x in n if x not in o]
        if gone and not is_output:
            a.bump("medium", "allowed value(s) removed: " + brief(gone, 60), "breaking")
        if new:
            a.bump("low", "allowed value(s) added: " + brief(new, 60), "widened")
        if not gone and not new:
            a.bump("info", "enum order changed")
        return

    if last == "type":
        a.bump("medium", f"type changed: {brief(a.old, 30)} -> {brief(a.new, 30)}", "breaking")
        return

    if last == "additionalProperties":
        if a.new is False and not is_output:
            a.bump("medium", "extra arguments are now rejected", "breaking")
        else:
            a.bump("low", "additionalProperties changed")
        return

    if last in ("minimum", "maximum", "minLength", "maxLength", "pattern", "format",
                "minItems", "maxItems", "exclusiveMinimum", "exclusiveMaximum", "const"):
        a.bump("low", f"validation constraint {last!r} changed", "breaking" if a.kind != "removed" else "widened")
        return

    if last == "default":
        a.bump("low", "default value changed")
        return

    a.bump("low", f"{which} changed")


def _assess_annotations(a: Assessed) -> bool:
    if "annotations" not in a.parts:
        return False
    last = a.parts[-1]
    new = a.new if not is_missing(a.new) else None
    old = a.old if not is_missing(a.old) else None
    if last == "destructiveHint" and new is True:
        a.bump("high", "tool now declares itself destructive", "security")
    elif last == "readOnlyHint" and old is True and new is not True:
        a.bump("high", "tool is no longer read-only", "security")
    elif last == "openWorldHint" and new is True:
        a.bump("medium", "tool now reaches external systems (openWorldHint)", "security")
    elif last == "idempotentHint" and old is True and new is not True:
        a.bump("low", "tool is no longer idempotent")
    elif last == "annotations" and isinstance(a.new, dict):
        if a.new.get("destructiveHint") is True:
            a.bump("high", "tool now declares itself destructive", "security")
        if a.new.get("openWorldHint") is True:
            a.bump("medium", "tool now reaches external systems (openWorldHint)", "security")
        a.bump("low", "annotations added")
    else:
        a.bump("low", f"annotation {last!r} changed")
    return True


def _scan_new_strings(a: Assessed, o: Any, n: Any, others: Sequence[str]) -> None:
    """Every string the change introduces (defaults, enums, consts, examples,
    nested descriptions, unknown fields) gets the same text checks."""
    before = set(t for _, t in iter_texts(o)) if not is_missing(o) else set()
    for tp, text in iter_texts(n, a.parts):
        if text in before:
            continue
        for sev, reason in _signals_at(tp, text, others):
            a.bump(sev, reason, "security")
    if a.kind == "added" and len(a.parts) >= 2 and a.parts[-2] == "properties":
        for sev, reason in name_signals(a.parts[-1]):
            a.bump(sev, "argument " + reason, "security")


def assess_changes(
    raw: Sequence[RawChange], old: Dict[str, Any], new: Dict[str, Any]
) -> List[Assessed]:
    """Score raw structural changes. Output order follows ``raw``."""
    names = _all_names(old, new)
    out: List[Assessed] = []
    for kind, parts, o, n in raw:
        if kind == "removed":
            detail = brief(o)
        elif kind == "added":
            detail = brief(n)
        else:
            detail = f"{brief(o)} -> {brief(n)}"
        a = Assessed(kind, join_path(parts), parts, detail, "info",
                     old=None if is_missing(o) else o, new=None if is_missing(n) else n)
        owner = _owner(parts)
        others = [x for x in names if x != owner]
        section = parts[0] if parts else ""

        if section == "server":
            if parts[1:2] == ("version",):
                a.bump("info", "server version changed")
            elif parts[1:2] == ("name",):
                a.bump("medium", "server identity (serverInfo.name) changed", "security")
            else:
                a.bump("low", "server capabilities changed")
        elif section in SECTIONS and len(parts) == 2:
            if kind == "added":
                _assess_entry_added(a, n, names)
            elif kind == "removed":
                a.bump("medium", f"{section[:-1]} removed (agents relying on it will break)", "breaking")
            else:
                a.bump("medium", f"{section[:-1]} replaced")
        elif section in SECTIONS and parts[-1] in TEXT_KEYS and isinstance(n if not is_missing(n) else None, str):
            a.bump("low", f"{parts[-1]} text changed (the model reads this verbatim)", "text")
            for sev, reason in _new_signals(None if is_missing(o) else o, n, others, _url_ok(parts)):
                a.bump(sev, reason, "security")
            if isinstance(o, str) and len(n) > 2 * len(o) + 200:
                a.bump("medium", f"text grew from {len(o)} to {len(n)} characters")
        elif section in SECTIONS and _assess_annotations(a):
            pass
        elif section in SECTIONS and _schema_context(parts) is not None:
            _assess_schema(a, old, new)
        elif section in SECTIONS:
            a.bump("low", "metadata changed")
        else:
            a.bump("low", "surface changed")
        if section in SECTIONS and (len(parts) > 2 or kind == "changed") and kind != "removed" and not (
                parts[-1] in TEXT_KEYS and isinstance(n, str)):
            _scan_new_strings(a, o, n, others)
        out.append(a.finish())
    return out


def scan_surface(surface: Dict[str, Any]) -> List[Assessed]:
    """Risk-scan a whole surface (e.g. the baseline lock). Pinning cannot catch
    a server that was poisoned *before* you snapshotted it; this can, for the
    same signals the drift scorer uses."""
    names = _all_names(surface)
    out: List[Assessed] = []
    for section in SECTIONS:
        entries = surface.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name in sorted(entries):
            entry = entries[name]
            others = [x for x in names if x != name]
            nsig = name_signals(name)
            if nsig:
                a = Assessed("present", join_path((section, name)), (section, name), repr(name), "info", new=name)
                for sev, reason in nsig:
                    a.bump(sev, reason, "security")
                out.append(a.finish())
            for parts, text in sorted(iter_texts(entry, (section, name))):
                sigs = _signals_at(parts, text, others)
                if sigs:
                    a = Assessed("present", join_path(parts), parts, brief(text), "info", new=text)
                    for sev, reason in sigs:
                        a.bump(sev, reason, "security")
                    out.append(a.finish())
            if isinstance(entry, dict):
                for parts, pname in sorted(iter_property_names(entry.get("inputSchema"), (section, name, "inputSchema"))):
                    nsig = name_signals(pname)
                    if _SENSITIVE_NAME.search(pname) or nsig:
                        a = Assessed("present", join_path(parts), parts, repr(pname), "info", new=pname)
                        if _SENSITIVE_NAME.search(pname):
                            a.bump("medium", f"argument has a sensitive-looking name: {pname!r}", "security")
                        for sev, reason in nsig:
                            a.bump(sev, "argument " + reason, "security")
                        out.append(a.finish())
    return out
