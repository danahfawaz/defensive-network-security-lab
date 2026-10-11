"""Compare two audit reports (JSON) to show what a remediation changed.

Findings are matched on ``(rule, device, object)``.  Devices are matched by name, or
through an explicit mapping when the "after" network renamed them (for example the
original lab's ``Router2`` became ``HQ-EDGE``).  A finding that moved from open to
accepted-risk counts as *accepted*, never as *resolved*: the weakness is still there.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .model import Severity

_ORDER = [s.label for s in sorted(Severity, reverse=True)]


class ReportError(Exception):
    """The file is not an audit report this version understands."""


def load_report(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data or "schema_version" not in data:
        raise ReportError(f"{path}: not a ciscoaudit JSON report")
    if str(data["schema_version"]).split(".")[0] != "1":
        raise ReportError(f"{path}: unsupported schema_version {data['schema_version']!r}")
    return data


def _worse(a: str, b: str) -> str:
    """The more severe of two severity labels."""
    return a if _ORDER.index(a) <= _ORDER.index(b) else b


def _counts(findings: list[dict]) -> dict[str, int]:
    out = {label: 0 for label in _ORDER}
    for f in findings:
        out[f["severity"]] += 1
    return out


def compare(before: dict, after: dict, device_map: dict[str, str] | None = None) -> dict:
    device_map = device_map or {}

    def key(f: dict, mapped: bool) -> tuple[str, str, str]:
        device = device_map.get(f["device"], f["device"]) if mapped else f["device"]
        return (f["rule_id"], device, f["object"])

    b_open = {key(f, True): f for f in before["findings"] if f["status"] == "open"}
    a_open = {key(f, False): f for f in after["findings"] if f["status"] == "open"}
    a_accepted = {key(f, False): f for f in after["findings"] if f["status"] == "accepted-risk"}

    resolved = [b_open[k] for k in b_open if k not in a_open and k not in a_accepted]
    accepted = [(b_open[k], a_accepted[k]) for k in b_open if k in a_accepted and k not in a_open]
    persisting = [(b_open[k], a_open[k]) for k in b_open if k in a_open]
    new = [a_open[k] for k in a_open if k not in b_open]

    before_devices = [d["name"] for d in before["devices"]]
    after_devices = [d["name"] for d in after["devices"]]
    mapped_before = {device_map.get(n, n): n for n in before_devices}
    unmatched_before = [n for m, n in mapped_before.items() if m not in after_devices]
    unmatched_after = [n for n in after_devices if n not in mapped_before]

    rules: dict[str, dict] = defaultdict(lambda: {"title": "", "severity": "info", "before": set(), "after": set(),
                                                    "accepted": set()})
    for f in before["findings"]:
        if f["status"] == "open":
            r = rules[f["rule_id"]]
            r["title"] = f["title"]
            r["before"].add(f["device"])
            r["severity"] = _worse(r["severity"], f["severity"])
    for f in after["findings"]:
        r = rules[f["rule_id"]]
        r["title"] = r["title"] or f["title"]
        r["severity"] = _worse(r["severity"], f["severity"])
        (r["after"] if f["status"] == "open" else r["accepted"]).add(f["device"])
    rule_rows = [
        {"rule_id": rid, "title": r["title"], "severity": r["severity"], "devices_before": len(r["before"]),
         "devices_after": len(r["after"]), "devices_accepted": len(r["accepted"])}
        for rid, r in sorted(rules.items(), key=lambda kv: (_ORDER.index(kv[1]["severity"]), kv[0]))
    ]

    def per_device(report: dict, mapping: dict[str, str] | None) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in report["findings"]:
            if f["status"] == "open":
                counts[(mapping or {}).get(f["device"], f["device"])] += 1
        return counts

    b_dev, a_dev = per_device(before, device_map), per_device(after, None)
    device_rows = [
        {"before": n, "after": device_map.get(n, n), "open_before": b_dev.get(device_map.get(n, n), 0),
         "open_after": a_dev.get(device_map.get(n, n), 0)}
        for n in before_devices
    ]

    return {
        "summary": {
            "open_before": _counts([f for f in before["findings"] if f["status"] == "open"]),
            "open_after": _counts([f for f in after["findings"] if f["status"] == "open"]),
            "accepted_after": _counts([f for f in after["findings"] if f["status"] == "accepted-risk"]),
            "resolved": len(resolved),
            "accepted_risk": len(accepted),
            "persisting": len(persisting),
            "new": len(new),
        },
        "rules": rule_rows,
        "devices": device_rows,
        "unmatched_before": unmatched_before,
        "unmatched_after": unmatched_after,
        "new_findings": new,
        "persisting_findings": [
            {"rule_id": a["rule_id"], "device": a["device"], "object": a["object"], "severity": a["severity"],
             "affected_before": len(b.get("affected", [])), "affected_after": len(a.get("affected", [])),
             "detail": a["detail"]}
            for b, a in persisting
        ],
        "accepted_findings": [
            {"rule_id": a["rule_id"], "device": a["device"], "object": a["object"], "severity": a["severity"],
             "reason": a.get("waiver_reason", "")}
            for _b, a in accepted
        ],
    }


def to_json(diff: dict) -> str:
    return json.dumps(diff, indent=2, ensure_ascii=False) + "\n"


def to_markdown(diff: dict, *, before_label: str = "Before", after_label: str = "After") -> str:
    s = diff["summary"]
    out = [f"# Remediation comparison: {before_label} → {after_label}", "",
           "## Open findings by severity", "", f"| Severity | {before_label} | {after_label} | Change | Accepted risk |",
           "|---|---:|---:|---:|---:|"]
    for label in _ORDER:
        b, a = s["open_before"][label], s["open_after"][label]
        out.append(f"| {label.capitalize()} | {b} | {a} | {a - b:+d} | {s['accepted_after'][label]} |")
    tb, ta = sum(s["open_before"].values()), sum(s["open_after"].values())
    out += [f"| **Total** | **{tb}** | **{ta}** | **{ta - tb:+d}** | **{sum(s['accepted_after'].values())}** |", "",
            f"Of the {tb} findings open before: **{s['resolved']} resolved**, **{s['accepted_risk']} accepted as risk** "
            f"(documented waiver), **{s['persisting']} still open**. **{s['new']} new** finding(s) appeared.", ""]
    out += ["## By rule", "", f"| Rule | Severity | Title | Devices {before_label} | Devices {after_label} | Accepted |",
            "|---|---|---|---:|---:|---:|"]
    for r in diff["rules"]:
        out.append(f"| {r['rule_id']} | {r['severity']} | {r['title']} | {r['devices_before']} | {r['devices_after']} | "
                   f"{r['devices_accepted']} |")
    out += ["", "## By device", "", f"| {before_label} device | {after_label} device | Open before | Open after |", "|---|---|---:|---:|"]
    for d in diff["devices"]:
        out.append(f"| {d['before']} | {d['after']} | {d['open_before']} | {d['open_after']} |")
    if diff["unmatched_before"] or diff["unmatched_after"]:
        out += ["", f"Unmatched devices - only before: {', '.join(diff['unmatched_before']) or 'none'}; "
                    f"only after: {', '.join(diff['unmatched_after']) or 'none'}."]
    for title, items in (("New findings (regressions)", diff["new_findings"]),):
        out += ["", f"## {title}", ""]
        out += [f"- {f['severity']} · {f['rule_id']} · {f['device']} · `{f['object']}`: {f['detail']}" for f in items] or ["None."]
    out += ["", "## Still open", ""]
    out += [f"- {p['severity']} · {p['rule_id']} · {p['device']} · `{p['object']}` "
            f"(affected {p['affected_before']} → {p['affected_after']}): {p['detail']}" for p in diff["persisting_findings"]] or ["None."]
    out += ["", "## Accepted risks", ""]
    out += [f"- {a['severity']} · {a['rule_id']} · {a['device']} · `{a['object']}`: {a['reason']}" for a in diff["accepted_findings"]] or ["None."]
    return "\n".join(out) + "\n"


def to_text(diff: dict) -> str:
    s = diff["summary"]
    tb, ta = sum(s["open_before"].values()), sum(s["open_after"].values())
    lines = [f"open findings: {tb} -> {ta}",
             f"resolved {s['resolved']}, accepted-risk {s['accepted_risk']}, still open {s['persisting']}, new {s['new']}"]
    for label in _ORDER:
        lines.append(f"  {label:8} {s['open_before'][label]:4} -> {s['open_after'][label]:4}")
    if diff["new_findings"]:
        lines.append("new findings:")
        lines += [f"  {f['severity']} {f['rule_id']} {f['device']}: {f['detail']}" for f in diff["new_findings"]]
    return "\n".join(lines) + "\n"
