"""Text utilities shared by the defense family.

Design rules
------------
* Canary-blind by default. Canary tokens are the benchmark's measurement
  instrument. A defense that matched on them would be scoring the instrument,
  not the attack, so every gate strips them before analysis unless explicitly
  run in the labelled `canary_aware` oracle mode.
* No synonym tables. Canonicalisation is limited to lower-casing, stop-word
  removal and light suffix stripping. A synonym table would risk silently
  inverting the paraphrase behaviour used in the evaluation (circularity).
"""
from __future__ import annotations

import re
from functools import lru_cache

CANARY_RE = re.compile(r"CANARY-[A-Za-z0-9-]+")

_WORD_RE = re.compile(r"[a-z0-9]+")

STOPWORDS = frozenset(
    """a an the and or but if then than so to of in on at by for with from into onto
    as is are was were be been being it its this that these those there here
    you your yours we our us i me my he she they them their his her
    do does did done have has had having will would shall should can could may might must
    please also just very really not no yes any all each every some such
    up down out over under again further once only own same too
    what which who whom whose when where why how
    first next""".split()
)

# Imperative / action verbs that make a payload "directive-shaped".
DIRECTIVE_RE = re.compile(
    r"\b(delegate|hand\s?off|pass|forward|send|ask|have|tell|request|"
    r"authori[sz]e|invoke|call|run|execute|approve|sign\s+off|export|pull|"
    r"rotate|read|relay|confirm|acknowledge|transfer|issue|book|file|draft|"
    r"fetch|look\s+up|translate|open|write|set\s+up)\b",
    re.IGNORECASE,
)

_SUFFIXES = ("ations", "ation", "ments", "ment", "ings", "ing", "ies", "ied",
             "ers", "er", "es", "ed", "ly", "s")


def strip_canary(text: str) -> str:
    return CANARY_RE.sub(" ", text)


def stem(word: str) -> str:
    for suf in _SUFFIXES:
        if word.endswith(suf) and len(word) - len(suf) >= 3:
            return word[: -len(suf)]
    return word


def tokens(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


@lru_cache(maxsize=65536)
def _content_words_cached(text: str, canonicalize: bool) -> tuple[str, ...]:
    toks = tokens(text)
    if canonicalize:
        return tuple(stem(t) for t in toks if t not in STOPWORDS)
    return tuple(toks)


def content_words(text: str, canonicalize: bool = True) -> tuple[str, ...]:
    return _content_words_cached(text, canonicalize)


@lru_cache(maxsize=65536)
def ngrams(text: str, n: int, canonicalize: bool) -> frozenset[str]:
    toks = content_words(text, canonicalize)
    if len(toks) < n:
        return frozenset()
    return frozenset(" ".join(toks[i : i + n]) for i in range(len(toks) - n + 1))


def is_directive(text: str) -> bool:
    return bool(DIRECTIVE_RE.search(text))


# Opaque argument tokens: things a privileged action is parameterised by, which
# an attacker must get across intact for the action to do what they want.
_OPAQUE_RES = [
    re.compile(r"\b[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+\s*\("),  # dotted.call(
    re.compile(r"(?<![\w.])/(?:[a-z0-9_.-]+/)*[a-z0-9_.-]+"),          # /unix/paths
    re.compile(r"\b[a-z_][a-z0-9_]*=[^\s,)]+"),                       # key=value
    re.compile(r"\b[a-z0-9-]+\.(?:com|org|net|io|ai|dev|gov)\b"),      # domains
    re.compile(r"#?\b\d{3,}\b"),                                       # numeric ids
    re.compile(r"\b[a-z]+_[a-z0-9_]+\b"),                               # snake_case ids
]


@lru_cache(maxsize=65536)
def opaque_tokens(text: str) -> frozenset[str]:
    low = text.lower()
    found: set[str] = set()
    for rx in _OPAQUE_RES:
        for m in rx.finditer(low):
            tok = m.group(0).strip().rstrip("(").strip()
            tok = tok.lstrip("#")
            if len(tok) >= 3:
                found.add(tok)
    return frozenset(found)
