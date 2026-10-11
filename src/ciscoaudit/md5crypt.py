"""MD5-crypt (``$1$``), the hash behind Cisco "type 5" secrets.

Implemented here because ``crypt`` was removed from the Python standard library.  The
auditor uses it for one thing only: to check whether a stored type-5 secret is one of
a short list of well-known passwords (the salt is part of the stored value, so a
dictionary check needs no secret information).  Verified against ``openssl passwd -1``.
"""

from __future__ import annotations

import hashlib

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ITOA64[value & 0x3F])
        value >>= 6
    return "".join(out)


def md5_crypt(password: str, salt: str) -> str:
    """Return the full ``$1$<salt>$<hash>`` string for ``password``."""
    pw = password.encode("utf-8")
    sl = salt.encode("ascii", "ignore")[:8]

    ctx = pw + b"$1$" + sl
    alt = hashlib.md5(pw + sl + pw).digest()
    remaining = len(pw)
    while remaining > 0:
        ctx += alt[: min(16, remaining)]
        remaining -= 16
    bit = len(pw)
    while bit:
        ctx += b"\x00" if bit & 1 else pw[:1]
        bit >>= 1
    final = hashlib.md5(ctx).digest()

    for i in range(1000):
        chunk = pw if i & 1 else final
        if i % 3:
            chunk += sl
        if i % 7:
            chunk += pw
        chunk += final if i & 1 else pw
        final = hashlib.md5(chunk).digest()

    f = final
    encoded = (
        _to64((f[0] << 16) | (f[6] << 8) | f[12], 4)
        + _to64((f[1] << 16) | (f[7] << 8) | f[13], 4)
        + _to64((f[2] << 16) | (f[8] << 8) | f[14], 4)
        + _to64((f[3] << 16) | (f[9] << 8) | f[15], 4)
        + _to64((f[4] << 16) | (f[10] << 8) | f[5], 4)
        + _to64(f[11], 2)
    )
    return f"$1${sl.decode('ascii')}${encoded}"


def split_hash(stored: str) -> tuple[str, str] | None:
    """``$1$salt$hash`` -> ``(salt, hash)``; ``None`` if it is not an MD5-crypt string."""
    if not stored.startswith("$1$"):
        return None
    parts = stored.split("$")
    if len(parts) != 4 or not parts[2] or not parts[3]:
        return None
    return parts[2], parts[3]
