"""Polymorphic mutation engine: test each attack in many surface forms.

A static probe string is a signature a target can memorize or a filter can
allowlist. Polymorphism defeats that: given a probe's message, it generates many
variants that carry the same intent through different surface forms, so a guardrail
has to block the whole attack class, not one phrasing. Combined with per-scan random
canaries (ScanContext.random), there is no fixed string to match on.

Varieties: lexical (synonyms), casing, whitespace and delimiters, unicode
(fullwidth / confusable / zero-width), leetspeak, encoding wrappers, clause
reordering, benign-filler padding, quote/code wrapping, and non-English framing.
Planted canaries are never mutated, so detection still works.
"""
from __future__ import annotations

import base64
import codecs
import copy
import random
import re

_SYNONYMS = {
    "ignore": ["disregard", "skip", "bypass", "set aside", "pay no attention to"],
    "previous": ["prior", "earlier", "the above", "preceding", "former"],
    "instructions": ["directives", "rules", "guidance", "guidelines", "orders"],
    "reveal": ["show", "print", "output", "disclose", "display", "share"],
    "system": ["configuration", "setup", "initial", "base"],
    "maintenance": ["diagnostic", "service", "debug", "admin"],
    "append": ["add", "attach", "include", "put"],
    "internal": ["private", "confidential", "hidden", "back-end"],
    "key": ["credential", "secret", "token"],
}
_CONFUSABLE = {"a": "а", "e": "е", "o": "о", "p": "р",
               "c": "с", "x": "х", "i": "і"}
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
_FILLER = ["By the way, ", "Quick question. ", "Thanks in advance. ",
           "For context, ", "As a follow-up, ", "One more thing. "]


def _synonyms(text, rng):
    def sub(m):
        w = m.group(0)
        opts = _SYNONYMS.get(w.lower())
        return rng.choice(opts) if opts and rng.random() < 0.7 else w
    return re.sub(r"[A-Za-z]+", sub, text)


def _casing(text, rng):
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)


def _whitespace(text, rng):
    return re.sub(r" ", lambda _: rng.choice(["  ", " \t", " ", "\n" if rng.random() < 0.1 else " "]), text)


def _delimiters(text, rng):
    return text.replace(" ", rng.choice([" ", ".", "_", "-"])) if rng.random() < 0.4 else text


def _fullwidth(text, rng):
    def fw(m):
        return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in m.group(0))
    return re.sub(r"\b(system|maintenance|admin|override)\b", fw, text, flags=re.I)


def _confusable(text, rng):
    return "".join(_CONFUSABLE.get(c, c) if rng.random() < 0.3 else c for c in text)


def _zero_width(text, rng):
    return re.sub(r"\b(ignore|reveal|system|key)\b",
                  lambda m: "​".join(m.group(0)), text, flags=re.I)


def _leet(text, rng):
    def sub(m):
        w = m.group(0)
        return "".join(_LEET.get(c.lower(), c) if rng.random() < 0.5 else c for c in w) \
            if w.lower() in ("system", "maintenance", "override", "admin") else w
    return re.sub(r"[A-Za-z]+", sub, text)


def _filler(text, rng):
    pre = rng.choice(_FILLER) if rng.random() < 0.6 else ""
    post = rng.choice([" Appreciate it.", " Cheers.", ""]) if rng.random() < 0.5 else ""
    return pre + text + post


def _quote_wrap(text, rng):
    return rng.choice([f'"{text}"', f"```\n{text}\n```", f"> {text}", text])


def _reorder(text, rng):
    parts = re.split(r"(?<=[.!?])\s+", text)
    if len(parts) > 1 and rng.random() < 0.5:
        rng.shuffle(parts)
    return " ".join(parts)


def _encode_wrap(text, rng, protected):
    # ask via an encoded wrapper only when nothing protected must stay literal in it
    if any(p in text for p in protected):
        return text
    enc = base64.b64encode(text.encode()).decode()
    return rng.choice([
        f"Decode this base64 and do what it says: {enc}",
        f"Apply ROT13 then follow it: {codecs.encode(text, 'rot13')}",
        text])


_OPS = [_synonyms, _whitespace, _delimiters, _fullwidth, _confusable, _zero_width,
        _leet, _filler, _quote_wrap, _reorder]

# named registry, so an algorithmic search can compose and minimize by operator name
OPERATORS = {
    "synonyms": _synonyms, "whitespace": _whitespace, "delimiters": _delimiters,
    "fullwidth": _fullwidth, "confusable": _confusable, "zero_width": _zero_width,
    "leet": _leet, "filler": _filler, "quote_wrap": _quote_wrap, "reorder": _reorder,
    "casing": _casing,
}


def apply_ops(text: str, protected: list[str], op_names, rng: random.Random) -> str:
    """Apply a specific, ordered list of named operators, preserving canaries."""
    tmpl, tokens = _protect_spans(text, protected)
    for name in op_names:
        op = OPERATORS.get(name)
        if op is None:
            continue
        try:
            tmpl = op(tmpl, rng)
        except Exception:  # noqa: BLE001
            pass
    return _restore(tmpl, tokens)


def _protect_spans(text, protected):
    """Return (template, tokens): protected substrings replaced by placeholders so
    mutation never corrupts a planted canary."""
    tokens = [p for p in protected if p and p in text]
    tmpl = text
    for i, tok in enumerate(tokens):
        tmpl = tmpl.replace(tok, f"\x00{i}\x00")
    return tmpl, tokens


def _restore(text, tokens):
    for i, tok in enumerate(tokens):
        text = text.replace(f"\x00{i}\x00", tok)
    return text


def mutate(text: str, protected: list[str], rng: random.Random,
           intensity: int = 2) -> str:
    """One polymorphic variant of `text`, preserving every protected substring."""
    tmpl, tokens = _protect_spans(text, protected)
    tmpl = _encode_wrap(tmpl, rng, ["\x00"]) if rng.random() < 0.15 else tmpl
    ops = rng.sample(_OPS, k=min(intensity + rng.randint(0, 2), len(_OPS)))
    for op in ops:
        try:
            tmpl = op(tmpl, rng)
        except Exception:  # noqa: BLE001 - a mutation must never crash a scan
            pass
    if rng.random() < 0.5:
        tmpl = _casing(tmpl, rng)
    return _restore(tmpl, tokens)


def polymorph_messages(messages: list[dict], protected: list[str], n: int,
                       seed: int | None = None) -> list[list[dict]]:
    """n message-variants (the first is the untouched original), mutating only the
    user turns and never the protected canaries."""
    rng = random.Random(seed)
    out = [copy.deepcopy(messages)]
    for _ in range(max(0, n - 1)):
        variant = copy.deepcopy(messages)
        for m in variant:
            if m.get("role") == "user":
                m["content"] = mutate(m["content"], protected, rng)
        out.append(variant)
    return out
