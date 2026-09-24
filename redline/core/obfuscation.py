"""Obfuscation transforms and a recursive decoder, from a measured red-team
bypass corpus (a measured corpus of confirmed real-world bypasses).

Every transform here defeated a naive decode-then-scan filter in testing. The
`recover()` function is the counter: it peels nested encodings (base64/hex/rot13/
gzip in any order, up to a depth bound), decodes unsupported codecs (base58, XOR,
decimal/hex charcode), reverses split-and-reorder tricks, and NFKC-folds unicode
confusables plus strips zero-width characters, then reports every decoded view so a
canary match can run against all of them.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import unicodedata

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)

# Cyrillic / Greek look-alikes NFKC does not fold (they are distinct letters).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "і": "i", "ԁ": "d", "ѕ": "s", "һ": "h",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ο": "O",
    "ο": "o", "А": "A", "В": "B", "С": "C", "Т": "T",
}


# --- transforms (build obfuscated forms of a value) ---

def to_base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * pad + out


def from_base58(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58_ALPHABET.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    if n == 0 and s:
        return b"\x00" * len(s)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(_B58_ALPHABET[0]))
    return b"\x00" * pad + out


def to_fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


def xor_decimals(data: bytes, key: int = 0x5A) -> str:
    return " ".join(str(b ^ key) for b in data)


def charcode_decimal(s: str) -> str:
    return " ".join(str(ord(c)) for c in s)


# --- recovery (decode obfuscated text to catch a hidden canary) ---

_B64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")
_DEC_RUN = re.compile(r"(?:\d{1,3}[ ,]){4,}\d{1,3}")


def _fold_unicode(s: str) -> str:
    s = s.translate(_ZERO_WIDTH)
    s = "".join(_CONFUSABLES.get(c, c) for c in s)
    return unicodedata.normalize("NFKC", s)


def _strip_sep(s: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", s)


def _try_layers(text: str) -> list[str]:
    """One pass of every reversible decode over `text`, returning new views."""
    out: list[str] = []

    def add(b: bytes | str):
        try:
            out.append(b.decode("utf-8", "ignore") if isinstance(b, bytes) else b)
        except Exception:  # noqa: BLE001
            pass

    try:
        add(codecs.decode(text, "rot13"))
    except Exception:  # noqa: BLE001
        pass
    for m in _B64_RE.findall(text):
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
            add(raw)
            if raw[:2] == b"\x1f\x8b":              # gzip magic
                add(gzip.decompress(raw))
        except (binascii.Error, ValueError, OSError):
            pass
    for m in _HEX_RE.findall(text):
        try:
            add(bytes.fromhex(m))
        except ValueError:
            pass
    for m in _DEC_RUN.findall(text):               # decimal charcodes / XOR decimals
        nums = [int(x) for x in re.split(r"[ ,]+", m.strip()) if x]
        if all(0 <= n < 256 for n in nums):
            add(bytes(nums))
            add(bytes((n ^ 0x5A) & 0xFF for n in nums))
    b58 = from_base58(text.strip())                # whole-string base58
    if b58:
        add(b58)
    add(text[::-1])                                 # reversed
    return out


def recover(text: str, max_depth: int = 4) -> list[str]:
    """Return `text` plus every decoded/normalized view, peeling nested layers."""
    seen = set()
    frontier = [_fold_unicode(text or "")]
    views = [text or "", frontier[0], _strip_sep(frontier[0])]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for t in frontier:
            for v in _try_layers(t):
                key = v[:200]
                if key in seen or not v:
                    continue
                seen.add(key)
                views.append(v)
                views.append(_strip_sep(v))
                nxt.append(v)
        frontier = nxt
        depth += 1
    return views


_TOKEN = re.compile(r"[0-9A-Za-z]+")


def reveals(text: str, needle: str) -> bool:
    """True if `needle` appears in any decoded view of `text` (separator-insensitive),
    including split-and-reordered fragments of the needle."""
    if not needle:
        return False
    n = needle.lower()
    ns = _strip_sep(n)
    frags = [f for f in re.split(r"[^0-9A-Za-z]+", n) if len(f) >= 2]
    for v in recover(text):
        lv = v.lower()
        if n in lv or (ns and ns in _strip_sep(lv)):
            return True
        # split/reorder: every needle fragment present as a standalone token
        if len(frags) >= 2:
            toks = set(_TOKEN.findall(lv))
            if all(f in toks for f in frags):
                return True
    return False
