"""Report writers: JSON (machine), Markdown (human), CSV (spreadsheet) and console text.

All writers print evidence through :func:`ciscoaudit.model.redact`, so credentials,
hashes and non-default SNMP communities never reach a report.  Reports contain no
timestamp unless asked for, which keeps them byte-for-byte reproducible and makes
``git diff`` on committed evidence meaningful.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import __version__
from .model import AuditResult, Finding, Severity, redact

SCHEMA_VERSION = "1.0"
_ORDER = sorted(Severity, reverse=True)
_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"


# =============================================================================
# Shared helpers
# =============================================================================


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.label: 0 for s in _ORDER}
    for f in findings:
        counts[f.severity.label] += 1
    return counts


def filter_by_severity(result: AuditResult, minimum: Severity | None) -> AuditResult:
    """A copy of ``result`` containing only findings at or above ``minimum``."""
    if minimum is None:
        return result
    clone = AuditResult(
        devices=result.devices,
        findings=[f for f in result.findings if f.severity >= minimum],
        rules_run=result.rules_run,
        scope=result.scope,
        warnings=result.warnings,
    )
    return clone


def summary(result: AuditResult) -> dict:
    open_f, waived = result.open_findings(), result.waived_findings()
    return {
        "devices": len(result.devices),
        "findings_open": len(open_f),
        "findings_accepted_risk": len(waived),
        "open_by_severity": _counts(open_f),
        "accepted_risk_by_severity": _counts(waived),
        "open_by_category": dict(sorted(Counter(f.category for f in open_f).items())),
    }


def _device_rows(result: AuditResult) -> list[dict]:
    rows = []
    for cfg in result.devices:
        mine = [f for f in result.findings if f.device == cfg.name]
        rows.append(
            {
                "name": cfg.name,
                "hostname": cfg.hostname,
                "file": cfg.path,
                "type": cfg.device_type,
                "model": cfg.model,
                "ios_version": cfg.ios_version,
                "open_by_severity": _counts([f for f in mine if not f.waived]),
                "accepted_risk": sum(1 for f in mine if f.waived),
            }
        )
    return rows


def _ev_line(e) -> str:
    where = f"L{e.line}" if e.line else "-"
    ctx = f"[{redact(e.context)}] " if e.context else ""
    return f"{where} {ctx}{redact(e.text)}"


def _group_by_rule(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule_id].append(f)
    return sorted(groups.items(), key=lambda kv: (-max(int(f.severity) for f in kv[1]), kv[0]))


# =============================================================================
# JSON
# =============================================================================


def to_dict(result: AuditResult, *, title: str | None = None, timestamp: bool = False,
            min_severity: Severity | None = None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "ciscoaudit", "version": __version__},
        "title": title or "Cisco configuration security audit",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds") if timestamp else None,
        "scope": {
            "files": result.scope,
            "rules_run": result.rules_run,
            "min_severity": min_severity.label if min_severity is not None else None,
        },
        "summary": summary(result),
        "devices": _device_rows(result),
        "findings": [f.to_dict() for f in result.findings],
        "warnings": result.warnings,
    }


def to_json(result: AuditResult, **kw) -> str:
    return json.dumps(to_dict(result, **kw), indent=2, ensure_ascii=False) + "\n"


# =============================================================================
# CSV
# =============================================================================

_CSV_FIELDS = ["severity", "rule_id", "title", "category", "device", "object", "status", "affected_count",
               "detail", "evidence", "remediation", "waiver_reason"]


def to_csv(result: AuditResult) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for f in result.findings:
        writer.writerow(
            {
                "severity": f.severity.label,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "device": f.device,
                "object": f.obj,
                "status": "accepted-risk" if f.waived else "open",
                "affected_count": len(f.affected),
                "detail": f.detail,
                "evidence": " | ".join(_ev_line(e) for e in f.evidence),
                "remediation": f.remediation,
                "waiver_reason": f.waiver_reason,
            }
        )
    return buf.getvalue()


# =============================================================================
# Markdown
# =============================================================================


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(result: AuditResult, *, title: str | None = None, min_severity: Severity | None = None) -> str:
    s = summary(result)
    out: list[str] = [f"# {title or 'Cisco configuration security audit'}", ""]
    scope = f"{s['devices']} configuration file(s) · {len(result.rules_run)} rules · ciscoaudit {__version__}"
    if min_severity is not None:
        scope += f" · showing {min_severity.label} and above"
    out += [f"*{scope}*", "", "## Summary", "", "| Severity | Open | Accepted risk |", "|---|---:|---:|"]
    for sev in _ORDER:
        out.append(f"| {sev.label.capitalize()} | {s['open_by_severity'][sev.label]} | {s['accepted_risk_by_severity'][sev.label]} |")
    out.append(f"| **Total** | **{s['findings_open']}** | **{s['findings_accepted_risk']}** |")

    out += ["", "## Devices", "", "| Device | Type | Model | Critical | High | Medium | Low | Info | Accepted risk |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for d in _device_rows(result):
        c = d["open_by_severity"]
        label = d["name"] + (f" (`{d['hostname']}`)" if d["hostname"] and d["hostname"] != d["name"] else "")
        out.append(f"| {label} | {d['type']} | {d['model'] or '-'} | {c['critical']} | {c['high']} | {c['medium']} | "
                   f"{c['low']} | {c['info']} | {d['accepted_risk']} |")

    open_groups = _group_by_rule(result.open_findings())
    out += ["", "## Findings", ""]
    if not open_groups:
        out += ["No open findings.", ""]
    for rule_id, findings in open_groups:
        head = findings[0]
        top = max(f.severity for f in findings)
        devices = sorted({f.device for f in findings})
        out += [f"### {top.label.upper()} · {rule_id} · {head.title}", "",
                f"*{head.category} · {len(devices)} device(s): {', '.join(devices)}*", "",
                f"**Risk.** {head.risk}", "", f"**Remediation.** {head.remediation}", ""]
        if head.references:
            out += ["**References.** " + "; ".join(head.references), ""]
        for f in findings:
            sev = f" ({f.severity.label})" if f.severity != top else ""
            out.append(f"- **{f.device}**{sev} - `{f.obj}`: {f.detail}")
            for e in f.evidence:
                out.append(f"  - `{_md_escape(_ev_line(e))}`")
        out.append("")

    waived_groups = _group_by_rule(result.waived_findings())
    if waived_groups:
        out += ["## Accepted risks", "",
                "These findings are acknowledged and waived; each keeps its written justification.", ""]
        for rule_id, findings in waived_groups:
            head = findings[0]
            out.append(f"### {rule_id} · {head.title}")
            out.append("")
            for f in findings:
                out.append(f"- **{f.device}** - `{f.obj}` ({f.severity.label}): {f.waiver_reason}")
            out.append("")

    if result.warnings:
        out += ["## Audit warnings", ""] + [f"- {w}" for w in result.warnings] + [""]
    return "\n".join(out).rstrip() + "\n"


# =============================================================================
# Console text
# =============================================================================


def to_text(result: AuditResult, *, color: bool = False, verbose: bool = False,
            min_severity: Severity | None = None) -> str:
    def tag(sev: Severity) -> str:
        label = f"{sev.label.upper():8}"
        return f"{_ANSI[sev]}{label}{_RESET}" if color else label

    s = summary(result)
    lines = [f"ciscoaudit {__version__}: {s['devices']} device(s), {len(result.rules_run)} rules"
             + (f", showing {min_severity.label}+" if min_severity is not None else "")]
    parts = [f"{s['open_by_severity'][sev.label]} {sev.label}" for sev in _ORDER]
    lines.append("open: " + ", ".join(parts) + f"   accepted risk: {s['findings_accepted_risk']}")
    lines.append("")
    for f in result.findings:
        status = " [accepted risk]" if f.waived else ""
        lines.append(f"{tag(f.severity)} {f.rule_id:9} {f.device}: {f.title}{status}")
        lines.append(f"{'':9} {f.detail}")
        if verbose:
            for e in f.evidence:
                lines.append(f"{'':11}{_ev_line(e)}")
            lines.append(f"{'':11}fix: {f.remediation}")
            if f.waived:
                lines.append(f"{'':11}accepted because: {f.waiver_reason}")
    if result.warnings:
        lines += ["", "warnings:"] + [f"  - {w}" for w in result.warnings]
    return "\n".join(lines) + "\n"


# =============================================================================
# Rule catalogue
# =============================================================================


def rules_to_dict(rules) -> list[dict]:
    return [
        {
            "id": r.info.id,
            "title": r.info.title,
            "severity": r.info.severity.label,
            "category": r.info.category,
            "applies_to": list(r.info.applies_to),
            "risk": r.info.risk,
            "remediation": r.info.remediation,
            "references": list(r.info.references),
        }
        for r in rules
    ]


def rules_to_json(rules) -> str:
    return json.dumps(rules_to_dict(rules), indent=2, ensure_ascii=False) + "\n"


def rules_to_text(rules) -> str:
    return "".join(
        f"{r.info.id:9} {r.info.severity.label:8} {r.info.category:17} {r.info.title}\n" for r in rules
    )


def rules_to_markdown(rules) -> str:
    out = ["# Rule catalogue", "",
           f"{len(rules)} rules. Generated by `ciscoaudit rules --format markdown`; do not edit by hand.", "",
           "| ID | Severity | Category | Applies to | Title |", "|---|---|---|---|---|"]
    for r in rules:
        i = r.info
        out.append(f"| [{i.id}](#{i.id.lower()}) | {i.severity.label} | {i.category} | {', '.join(i.applies_to)} | {i.title} |")
    for r in rules:
        i = r.info
        out += ["", f"## {i.id}", "", f"**{i.title}** · {i.severity.label} · {i.category} · applies to {', '.join(i.applies_to)}", "",
                f"**Risk.** {i.risk}", "", f"**Remediation.** {i.remediation}"]
        if i.references:
            out += ["", "**References.** " + "; ".join(i.references)]
    return "\n".join(out) + "\n"
