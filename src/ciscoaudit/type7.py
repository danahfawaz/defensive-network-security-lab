"""Cisco "type 7" password obfuscation.

Type 7 is **not encryption**: it is a Vigenere-style XOR against a fixed, publicly
documented 53-byte table, so every type-7 string can be reversed instantly. The
auditor uses :func:`decode` for one purpose only - to check whether a stored
credential is one of a handful of well-known weak passwords. Decoded values are
never written to reports or logs.
"""

from __future__ import annotations

import re

_XLAT = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
assert len(_XLAT) == 53

_TYPE7_RE = re.compile(r"^(?P<seed>\d{2})(?P<hex>(?:[0-9A-Fa-f]{2})+)$")


def is_type7(value: str) -> bool:
    """Return True if ``value`` is shaped like a type-7 string (seed + hex pairs)."""
    match = _TYPE7_RE.match(value)
    return bool(match) and int(match.group("seed")) < 53


def decode(value: str) -> str | None:
    """Reverse a type-7 string; ``None`` if it is not a valid type-7 value."""
    match = _TYPE7_RE.match(value)
    if not match:
        return None
    seed = int(match.group("seed"))
    if seed >= len(_XLAT):
        return None
    raw = bytes.fromhex(match.group("hex"))
    return "".join(chr(b ^ ord(_XLAT[(seed + i) % len(_XLAT)])) for i, b in enumerate(raw))


def encode(plaintext: str, seed: int = 7) -> str:
    """Produce a type-7 string (used by the test-suite and the config renderer)."""
    if not 0 <= seed < len(_XLAT):
        raise ValueError("seed must be in 0..52")
    body = "".join(f"{ord(c) ^ ord(_XLAT[(seed + i) % len(_XLAT)]):02X}" for i, c in enumerate(plaintext))
    return f"{seed:02d}{body}"
