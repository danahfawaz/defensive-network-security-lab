"""Credential-storage rules (CRED-*)."""

from __future__ import annotations

from dataclasses import dataclass

from .. import type7
from ..md5crypt import md5_crypt, split_hash
from ..model import Severity
from ..parser import ConfigLine, DeviceConfig
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_PWD, Hit, attack, rule

# A deliberately short list: it exists to catch lab/default passwords, not to crack anything.
# Matches are reported without revealing which word matched.
WEAK_PASSWORDS = (
    "cisco", "class", "admin", "password", "123456", "12345", "1234", "cisco123", "secret", "test",
    "letmein", "changeme", "default", "root", "lab", "switch", "router", "cisco1", "admin123", "p@ssw0rd",
    "password1", "welcome", "qwerty", "abc123", "toor", "enable", "telnet", "ciscoccna", "cisco1234", "ccna",
)


@dataclass(frozen=True)
class Credential:
    where: str  # "enable password", "username ops", "line vty 0 4", ...
    kind: str  # "password" | "secret"
    enc_type: int | None
    value: str
    line: ConfigLine

    @property
    def storage(self) -> str:
        """plain | type7 | md5 | type4 | type8 | type9 | unknown"""
        t = self.enc_type
        if t in (None, 0):
            return "plain"
        if self.kind == "password":
            return "type7" if t == 7 else "unknown"
        return {4: "type4", 5: "md5", 8: "type8", 9: "type9"}.get(t, "unknown")


def credentials(cfg: DeviceConfig) -> list[Credential]:
    """Every password or secret stored in the configuration."""
    found: list[Credential] = []
    for line in cfg.top("enable"):
        if len(line.words) < 3 or line.words[1] not in ("password", "secret"):
            continue
        tokens = line.text.split()
        idx = 2
        if tokens[idx].lower() == "level" and len(tokens) > idx + 2:
            idx += 2
        enc: int | None = None
        if len(tokens) > idx + 1 and tokens[idx].isdigit() and len(tokens[idx]) == 1:
            enc, idx = int(tokens[idx]), idx + 1
        if idx < len(tokens):
            found.append(Credential(f"enable {line.words[1]}", line.words[1], enc, tokens[idx], line))
    for user in cfg.users:
        if user.kind in ("secret", "password") and user.value is not None:
            found.append(Credential(f"username {user.name}", user.kind, user.enc_type, user.value, user.line))
    for blk in cfg.line_blocks:
        pw = blk.password
        if pw is not None:
            found.append(Credential(blk.label, "password", pw[0], pw[1], pw[2]))
    return found


def _is_weak(cred: Credential) -> bool:
    weak = set(WEAK_PASSWORDS)
    storage = cred.storage
    if storage == "plain":
        return cred.value.lower() in weak
    if storage == "type7":
        plain = type7.decode(cred.value)
        return plain is not None and plain.lower() in weak
    if storage == "md5":
        parts = split_hash(cred.value)
        if parts is None:
            return False
        salt = parts[0]
        return any(md5_crypt(word, salt) == cred.value for word in WEAK_PASSWORDS)
    return False


@rule(
    id="CRED-001",
    title="No enable secret is configured",
    severity=Severity.HIGH,
    category="Credentials",
    risk=(
        "With no enable secret, privileged EXEC is not password-protected at the console, so physical or console-server "
        "access means full control; remote users cannot elevate, which tempts administrators into giving every account "
        "privilege 15 instead."
    ),
    remediation="Set a strong, unique secret: 'enable secret <value>' (stored as a hash). Do not use 'enable password'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_PWD),
)
def no_enable_secret(cfg: DeviceConfig):
    has_secret = any(l.words[1:2] == ("secret",) and "level" not in l.words for l in cfg.top("enable"))
    has_password = any(l.words[1:2] == ("password",) and "level" not in l.words for l in cfg.top("enable"))
    if not has_secret and not has_password:
        yield Hit(obj="global", detail="Neither 'enable secret' nor 'enable password' is configured.")


@rule(
    id="CRED-002",
    title="Credentials are stored in clear text or in reversible form",
    severity=Severity.HIGH,
    category="Credentials",
    risk=(
        "Type 0 is plain text and type 7 is a reversible Vigenere-style encoding that public tools undo instantly. Anyone "
        "who can read a configuration backup, a TFTP capture or a screen share recovers the password."
    ),
    remediation=(
        "Replace 'enable password' with 'enable secret'; use 'username <name> secret <value>' instead of 'password'; "
        "prefer 'login local' to line passwords. Enable 'service password-encryption' only as a second line of defence."
    ),
    references=(attack("T1552.001", "Unsecured Credentials: Credentials In Files"), REF_NSA_PWD, REF_CIS_IOS),
)
def reversible_credentials(cfg: DeviceConfig):
    bad = [c for c in credentials(cfg) if c.storage in ("plain", "type7")]
    if bad:
        plain = sum(1 for c in bad if c.storage == "plain")
        yield Hit(
            obj="credentials",
            detail=f"{len(bad)} credential(s) are recoverable from the configuration "
            f"({plain} in clear text, {len(bad) - plain} type 7): " + ", ".join(c.where for c in bad) + ".",
            evidence=[c.line for c in bad],
            affected=[c.where for c in bad],
        )


@rule(
    id="CRED-003",
    title="Weak password hash algorithm (type 4)",
    severity=Severity.MEDIUM,
    category="Credentials",
    risk=(
        "Type 4 secrets use a SHA-256 construction without a proper salt or iteration count, so they can be cracked "
        "offline much faster than type 5 and far faster than type 8 or 9. Cisco and the NSA advise against using it."
    ),
    remediation="Re-enter the secret with a stronger type where the platform supports it ('algorithm-type scrypt' for type 9).",
    references=(REF_NSA_PWD,),
)
def type4_secret(cfg: DeviceConfig):
    bad = [c for c in credentials(cfg) if c.storage == "type4"]
    if bad:
        yield Hit(obj="credentials", detail="Type 4 hash used by: " + ", ".join(c.where for c in bad) + ".",
                  evidence=[c.line for c in bad], affected=[c.where for c in bad])


@rule(
    id="CRED-004",
    title="A well-known or default password is in use",
    severity=Severity.CRITICAL,
    category="Credentials",
    risk=(
        "Passwords such as 'cisco' or 'admin' are the first guesses of every attacker and scanner. The check works even "
        "on hashed values because the salt is stored with the hash."
    ),
    remediation="Replace the credential with a unique passphrase (14+ characters) and rotate anything derived from it.",
    references=(attack("T1078.001", "Valid Accounts: Default Accounts"), attack("T1110.001", "Brute Force: Password Guessing"),
                REF_NSA_PWD),
)
def weak_password(cfg: DeviceConfig):
    bad = [c for c in credentials(cfg) if _is_weak(c)]
    if bad:
        yield Hit(
            obj="credentials",
            detail="Matches the built-in list of well-known passwords (the value is deliberately not shown): "
            + ", ".join(c.where for c in bad) + ".",
            evidence=[c.line for c in bad],
            affected=[c.where for c in bad],
        )


@rule(
    id="CRED-005",
    title="'service password-encryption' is not enabled",
    severity=Severity.MEDIUM,
    category="Credentials",
    risk=(
        "Line and username passwords that are not otherwise hashed appear in clear text in 'show running-config'. The "
        "service adds type 7 obfuscation, which is weak, but it stops casual disclosure by shoulder-surfing or a pasted "
        "screenshot."
    ),
    remediation="'service password-encryption', and store credentials with 'secret' so they are hashed in the first place.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
)
def password_encryption_off(cfg: DeviceConfig):
    state, line = cfg.state("service", "password-encryption")
    if state:
        return
    exposed = [c for c in credentials(cfg) if c.storage == "plain"]
    yield Hit(
        obj="global",
        detail=("'service password-encryption' is off" + (" (explicitly disabled)" if line else "")
                + (f" and {len(exposed)} credential(s) are stored in clear text." if exposed
                   else "; no clear-text credentials are present right now.")),
        evidence=[line] if line else [],
        severity=Severity.MEDIUM if exposed else Severity.LOW,
    )
