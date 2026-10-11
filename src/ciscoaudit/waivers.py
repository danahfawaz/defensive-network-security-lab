"""Accepted-risk waivers.

A waiver says "we know about this finding and accept it, for this reason".  It never
deletes a finding: waived findings stay in every report with ``status: accepted-risk``
and the written reason, so a reviewer can challenge them.  A waiver needs a reason,
may expire, and unknown keys are rejected so that a typo cannot silently widen it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

from .model import Finding

_ALLOWED_KEYS = {"rule", "device", "object", "reason", "expires"}


class WaiverError(Exception):
    """The waiver file is malformed."""


@dataclass(frozen=True)
class Waiver:
    rule: str  # rule id or glob, e.g. "MGMT-009" or "LOG-*"
    reason: str
    device: str = "*"  # glob on the device name
    object: str = "*"  # glob on the finding's object label
    expires: date | None = None
    source: str = ""

    def matches(self, finding: Finding) -> bool:
        return (
            fnmatch.fnmatchcase(finding.rule_id, self.rule.upper())
            and fnmatch.fnmatchcase(finding.device, self.device)
            and fnmatch.fnmatchcase(finding.obj, self.object)
        )

    def describe(self) -> str:
        return f"{self.source or 'waiver'} ({self.rule} on {self.device})"


def load_waivers(path: str | Path) -> list[Waiver]:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise WaiverError(f"{path}: {exc}") from exc
    if data is None:
        return []
    entries = data.get("waivers") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise WaiverError(f"{path}: expected a top-level 'waivers:' list")
    waivers = []
    for index, entry in enumerate(entries, 1):
        where = f"{p.name}#{index}"
        if not isinstance(entry, dict):
            raise WaiverError(f"{where}: each waiver must be a mapping")
        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            raise WaiverError(f"{where}: unknown key(s) {sorted(unknown)}; allowed: {sorted(_ALLOWED_KEYS)}")
        if not entry.get("rule"):
            raise WaiverError(f"{where}: 'rule' is required")
        reason = str(entry.get("reason") or "").strip()
        if not reason:
            raise WaiverError(f"{where}: 'reason' is required - an accepted risk must be justified")
        expires = entry.get("expires")
        if expires is not None and not isinstance(expires, date):
            try:
                expires = date.fromisoformat(str(expires))
            except ValueError as exc:
                raise WaiverError(f"{where}: 'expires' must be an ISO date (YYYY-MM-DD)") from exc
        waivers.append(
            Waiver(
                rule=str(entry["rule"]),
                reason=reason,
                device=str(entry.get("device", "*")),
                object=str(entry.get("object", "*")),
                expires=expires,
                source=where,
            )
        )
    return waivers


def apply_waivers(findings: list[Finding], waivers: list[Waiver], today: date) -> list[str]:
    """Mark matching findings as accepted risk; return notes about expired or stale waivers."""
    notes: list[str] = []
    used: set[int] = set()
    for index, waiver in enumerate(waivers):
        if waiver.expires is not None and waiver.expires < today:
            notes.append(f"{waiver.describe()} expired on {waiver.expires}; matching findings stay open")
    for finding in findings:
        for index, waiver in enumerate(waivers):
            if waiver.expires is not None and waiver.expires < today:
                continue
            if waiver.matches(finding):
                finding.waived = True
                finding.waiver_reason = waiver.reason
                used.add(index)
                break
    for index, waiver in enumerate(waivers):
        expired = waiver.expires is not None and waiver.expires < today
        if index not in used and not expired:
            notes.append(f"{waiver.describe()} matched no finding (stale waiver?)")
    return notes
