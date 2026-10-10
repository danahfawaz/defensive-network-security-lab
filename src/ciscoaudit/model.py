"""Data model shared by the auditor, the report writers and the policy validator."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity. Ordered so that comparisons (``>=``) behave naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:  # pragma: no cover - message only
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from exc


@dataclass(frozen=True)
class Evidence:
    """One configuration line that supports a finding."""

    line: int | None
    text: str
    context: str | None = None  # the parent command, e.g. "line vty 0 4"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"line": self.line, "text": redact(self.text)}
        if self.context:
            data["context"] = redact(self.context)
        return data


@dataclass
class Finding:
    """A single security finding on one device."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    device: str
    file: str
    obj: str
    detail: str
    evidence: list[Evidence]
    risk: str
    remediation: str
    references: tuple[str, ...] = ()
    affected: list[str] = field(default_factory=list)  # e.g. the interface names behind an aggregated finding
    waived: bool = False
    waiver_reason: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable identity used to diff two audits (rule + device + affected object)."""
        return f"{self.rule_id}|{self.device}|{self.obj}"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "device": self.device,
            "file": self.file,
            "object": self.obj,
            "affected": list(self.affected),
            "detail": self.detail,
            "evidence": [e.to_dict() for e in self.evidence],
            "risk": self.risk,
            "remediation": self.remediation,
            "references": list(self.references),
            "status": "accepted-risk" if self.waived else "open",
        }
        if self.waived:
            data["waiver_reason"] = self.waiver_reason
        return data


# --------------------------------------------------------------------------
# Secret redaction. Reports are meant to be committed and shared, so a finding
# must never echo a password, a hash, a key or a non-default SNMP community.
# --------------------------------------------------------------------------
_REDACTED = "<redacted>"
_WELL_KNOWN_SNMP = {"public", "private"}

_SECRET_RES = [
    # enable password/secret [level N] [type] VALUE, line "password [type] VALUE", username ... secret/password [type] VALUE
    re.compile(
        r"(?P<pre>\b(?:enable\s+(?:password|secret)(?:\s+level\s+\d+)?|password|secret)\s+(?:\d\s+)?)(?P<val>\S+)",
        re.IGNORECASE,
    ),
    re.compile(r"(?P<pre>\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)(?P<val>\S+)", re.IGNORECASE),
    re.compile(r"(?P<pre>\bauthentication-key\s+(?:\d\s+)?)(?P<val>\S+)", re.IGNORECASE),
    re.compile(r"(?P<pre>\bkey-string\s+(?:\d\s+)?)(?P<val>\S+)", re.IGNORECASE),
    re.compile(
        r"(?P<pre>\b(?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)(?P<val>\S+)",
        re.IGNORECASE,
    ),
]
_SNMP_RE = re.compile(r"(?P<pre>\bsnmp-server\s+community\s+)(?P<val>\S+)", re.IGNORECASE)


def redact(text: str) -> str:
    """Return ``text`` with credential values replaced by ``<redacted>``."""

    def _mask(match: "re.Match[str]") -> str:
        return match.group("pre") + _REDACTED

    for pattern in _SECRET_RES:
        text = pattern.sub(_mask, text)

    def _snmp(match: "re.Match[str]") -> str:
        value = match.group("val")
        if value.lower() in _WELL_KNOWN_SNMP:
            return match.group(0)
        return match.group("pre") + _REDACTED

    return _SNMP_RE.sub(_snmp, text)


@dataclass
class AuditResult:
    """Everything produced by one audit run."""

    devices: list[Any] = field(default_factory=list)  # list[DeviceConfig]
    findings: list[Finding] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.waived]

    def waived_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.waived]

    def count_by_severity(self, *, include_waived: bool = False) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for finding in self.findings:
            if finding.waived and not include_waived:
                continue
            counts[finding.severity.label] += 1
        return counts
