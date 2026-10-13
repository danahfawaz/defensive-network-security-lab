"""Reports for ``ciscoaudit validate``: text, Markdown, JSON and CSV, plus the Packet Tracer test plan."""

from __future__ import annotations

import csv
import io
import json

from .scenarios import CATEGORIES, Outcome, Scenario, ScenarioResult, ValidationRun
from .topology import Topology

_STATE_TITLE = {"baseline": "Baseline", "hardened": "Hardened"}
_MARK = {"pass": "PASS", "fail": "FAIL", "info": "info", "pending": "pending"}
_DISCLAIMER = (
    "These results are computed offline from the configuration files in `configs/` and the lab design in "
    "`topology/topology.yaml`. They say what the configurations do. They are **not** Packet Tracer results: no scenario "
    "listed here has been run in Packet Tracer unless a row in `evidence/packet-tracer/` says so."
)


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _short(outcome: Outcome) -> str:
    """The result of one scenario in a few words."""
    if outcome.status == "pending":
        return "pending"
    if outcome.actual == "blocked":
        by = f"{outcome.blocked_by} @ {outcome.at}" if outcome.blocked_by else "blocked"
        return f"blocked ({by}{', ' + outcome.phase if outcome.phase == 'reply' else ''})"
    return outcome.actual


# --------------------------------------------------------------------------------------------------------------------
# text
# --------------------------------------------------------------------------------------------------------------------


def to_text(run: ValidationRun, *, verbose: bool = False) -> str:
    lines = []
    for state in run.states:
        counts = {k: run.count(state, k) for k in ("pass", "fail", "info", "pending")}
        design = "design checks OK" if run.design_ok.get(state, True) else "DESIGN CHECKS FAIL"
        lines.append(f"{state}: {counts['pass']} passed, {counts['fail']} failed, {counts['info']} informational, "
                     f"{counts['pending']} pending (manual)   [{design}]")
    lines.append("")
    width = max(len(r.scenario.id) for r in run.results)
    for r in run.results:
        parts = [f"{r.scenario.id:<{width}}", f"{r.scenario.category:<10}"]
        for state in run.states:
            o = r.outcomes[state]
            parts.append(f"{state[:4]} {_MARK[o.status]:<7} {_short(o):<44}")
        parts.append(r.scenario.title)
        lines.append("  ".join(parts))
    failures = run.failures
    if failures:
        lines += ["", f"{len(failures)} FAILURE(S):"]
        for r, o in failures:
            lines.append(f"  {r.scenario.id} [{o.state}] {r.scenario.title}\n      {o.detail}")
            if verbose and o.trace:
                lines += [f"        {h}" for h in o.trace]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------------------------------
# JSON / CSV
# --------------------------------------------------------------------------------------------------------------------


def _scenario_dict(sc: Scenario) -> dict:
    return {
        "id": sc.id, "title": sc.title, "category": sc.category, "kind": sc.kind, "threats": list(sc.threats),
        "flow": str(sc.flow) if sc.flow else None, "check": sc.check or None, "expect": sc.expect or None,
        "baseline_expect": sc.baseline, "by": sc.by, "at": sc.at, "phase": sc.phase, "limitation": sc.limitation or None,
        "note": sc.note or None,
    }


def to_json(run: ValidationRun) -> str:
    results = []
    for r in run.results:
        entry = _scenario_dict(r.scenario)
        entry["results"] = {
            state: {
                "status": o.status, "actual": o.actual, "detail": o.detail, "blocked_by": o.blocked_by, "at": o.at,
                "phase": o.phase, "request_trace": o.trace, "reply_trace": o.reply_trace,
            }
            for state, o in r.outcomes.items()
        }
        results.append(entry)
    summary = {state: {k: run.count(state, k) for k in ("pass", "fail", "info", "pending")} for state in run.states}
    return json.dumps({"summary": summary, "design_checks_ok": run.design_ok, "scenarios": results,
                       "note": "computed offline from the configuration files; not Packet Tracer results"}, indent=2) + "\n"


def to_csv(run: ValidationRun) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    header = ["id", "category", "kind", "title", "flow_or_check"]
    for state in run.states:
        header += [f"{state}_expected", f"{state}_actual", f"{state}_status", f"{state}_stopped_by", f"{state}_at"]
    w.writerow(header)
    for r in run.results:
        sc = r.scenario
        row = [sc.id, sc.category, sc.kind, sc.title, str(sc.flow) if sc.flow else json.dumps(sc.check) if sc.check else ""]
        for state in run.states:
            o = r.outcomes[state]
            row += [sc.expected(state) or "", o.actual, o.status, o.blocked_by or "", o.at or ""]
        w.writerow(row)
    return buf.getvalue()


# --------------------------------------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------------------------------------


def _summary_table(run: ValidationRun) -> list[str]:
    head = "| | " + " | ".join(_STATE_TITLE.get(s, s) for s in run.states) + " |"
    sep = "|---|" + "---:|" * len(run.states)
    rows = [head, sep]
    for label, key in (("Scenarios that passed", "pass"), ("Scenarios that failed", "fail"),
                       ("Informational (no expectation asserted)", "info"), ("Pending (need Packet Tracer)", "pending")):
        rows.append(f"| {label} | " + " | ".join(str(run.count(s, key)) for s in run.states) + " |")
    rows.append("| Design checks (config matches topology) | " + " | ".join("OK" if run.design_ok.get(s, True) else "FAIL" for s in run.states) + " |")
    return rows


def to_markdown(run: ValidationRun, *, title: str = "Security validation report") -> str:
    both = "baseline" in run.states and "hardened" in run.states
    lines = [f"# {title}", "", f"> {_DISCLAIMER}", "", "## Summary", "", *_summary_table(run), ""]
    if run.failures:
        lines += ["## Failures", ""]
        for r, o in run.failures:
            lines.append(f"- **{r.scenario.id}** ({o.state}) {r.scenario.title}: {o.detail}")
        lines.append("")
    by_cat: dict[str, list[ScenarioResult]] = {}
    for r in run.results:
        by_cat.setdefault(r.scenario.category, []).append(r)
    for category, label in CATEGORIES.items():
        items = by_cat.get(category)
        if not items:
            continue
        lines += [f"## {label}", ""]
        if both:
            lines += ["| ID | Scenario | Baseline | Hardened | Why (hardened) |", "|---|---|---|---|---|"]
        else:
            state = run.states[0]
            lines += [f"| ID | Scenario | {_STATE_TITLE.get(state, state)} | Why |", "|---|---|---|---|"]
        for r in items:
            sc = r.scenario
            flow = f"<br>`{sc.flow}`" if sc.flow else ""
            if both:
                b, h = r.outcomes["baseline"], r.outcomes["hardened"]
                lines.append(f"| {sc.id} | {_cell(sc.title)}{flow} | {_cell(_short(b))} | {_cell(_mark_result(h))} | {_cell(_why(h))} |")
            else:
                o = r.outcomes[run.states[0]]
                lines.append(f"| {sc.id} | {_cell(sc.title)}{flow} | {_cell(_mark_result(o))} | {_cell(_why(o))} |")
        lines.append("")
    lines += [
        "## How to read this", "",
        "- **delivered**: the request reaches its destination and, for connections, the reply comes back.",
        "- **blocked (X @ Y)**: stopped by ACL `X` (or by `route`, `vty`, `no-service`) on device `Y`; `, reply` means the "
        "request got through but the answer was stopped.",
        "- Baseline results are asserted wherever a scenario states one; a mismatch is reported as a failure, so the "
        "'before' column is a fact about the baseline configurations, not a claim.",
        "",
    ]
    return "\n".join(lines)


def _mark_result(o: Outcome) -> str:
    return f"{_short(o)}" if o.status in ("pending", "info") else f"{_short(o)} - {_MARK[o.status]}"


def _why(o: Outcome) -> str:
    if o.status == "pending":
        return "see docs/pt-test-plan.md"
    if o.status == "fail":
        return o.detail
    return o.detail


# --------------------------------------------------------------------------------------------------------------------
# Packet Tracer test plan
# --------------------------------------------------------------------------------------------------------------------


def _pt_method(sc: Scenario, topology: Topology) -> tuple[str, str]:
    """(how to run it in Packet Tracer, note). Returns ('', note) if a stock PC cannot send this packet."""
    f = sc.flow
    assert f is not None
    if sc.pt.get("method"):
        return sc.pt["method"], sc.pt.get("note", "")
    if f.spoof is not None:
        return "", "A PC cannot forge its source address; this is verified by simulation only."
    if f.ack:
        return "", "A PC cannot send a bare ACK packet; this is verified by simulation only."
    if f.src in topology.devices:
        return "", "Traffic generated by the device itself; check it on the receiving server or with the device's own commands."
    dst = f.dst
    if f.proto == "icmp":
        return f"{f.src} > Desktop > Command Prompt: `ping {_address(topology, dst)}`", ""
    if f.proto == "tcp" and f.dport == 80:
        return f"{f.src} > Desktop > Web Browser: `http://{_address(topology, dst)}`", ""
    if f.proto == "tcp" and f.dport == 443:
        return f"{f.src} > Desktop > Web Browser: `https://{_address(topology, dst)}`", "[PT-VERIFY] HTTPS on the Server-PT"
    if f.proto == "tcp" and f.dport == 22:
        return f"{f.src} > Desktop > Command Prompt: `ssh -l admin {_address(topology, dst)}`", ""
    if f.proto == "tcp" and f.dport == 23:
        return f"{f.src} > Desktop > Command Prompt: `telnet {_address(topology, dst)}`", ""
    port = f"{f.proto.upper()}/{f.dport}"
    return (f"{f.src}: Add Complex PDU ({port}) to {_address(topology, dst)} in Simulation mode",
            "[PT-VERIFY] Complex PDU options")


def _address(topology: Topology, name: str) -> str:
    if name in topology.hosts:
        return str(topology.hosts[name].ip)
    if name in topology.management:
        return str(topology.management[name])
    return name


def pt_plan_rows(run: ValidationRun, topology: Topology) -> list[dict]:
    rows = []
    for r in run.results:
        sc = r.scenario
        if sc.kind == "manual":
            rows.append({"id": sc.id, "title": sc.title, "how": " ".join(f"({i}) {s}" for i, s in enumerate(sc.steps, 1)),
                         "predicted": "see steps", "note": "manual check", "testable": True})
            continue
        if sc.kind == "audit":
            continue
        out = r.outcomes["hardened"]
        how, note = _pt_method(sc, topology)
        predicted = "succeeds" if out.actual == "delivered" else "fails / no answer"
        rows.append({"id": sc.id, "title": sc.title, "how": how or "not testable with a stock PC", "predicted": predicted,
                     "note": note, "testable": bool(how), "simulator_says": _short(out)})
    return rows


def pt_plan_markdown(run: ValidationRun, topology: Topology) -> str:
    rows = pt_plan_rows(run, topology)
    testable = [r for r in rows if r["testable"] and not r["id"].startswith("X-")]
    manual = [r for r in rows if r["id"].startswith("X-")]
    sim_only = [r for r in rows if not r["testable"]]
    lines = [
        "# Packet Tracer test plan",
        "",
        "Generated by `ciscoaudit validate --pt-plan` from `scenarios/scenarios.yaml`; do not edit by hand.",
        "",
        "Run each test on the hardened network (after pasting the rendered configurations, see `docs/packet-tracer-build.md`) "
        "and record the outcome in `evidence/packet-tracer/results.csv`. The **Simulator predicts** column is what the "
        "configuration files imply; whether Packet Tracer agrees is exactly what these tests find out. A disagreement "
        "is a finding, not an error in this document: record it.",
        "",
        "Result vocabulary for the CSV: `succeeded` (the request worked), `blocked` (it failed or timed out), "
        "`not-supported` (Packet Tracer rejected the command or lacks the feature), `not-run`.",
        "",
        f"## 1. Traffic tests ({len(testable)})",
        "",
        "| ID | Test | Do this in Packet Tracer | Simulator predicts | Note |",
        "|---|---|---|---|---|",
    ]
    for r in testable:
        lines.append(f"| {r['id']} | {_cell(r['title'])} | {_cell(r['how'])} | {r['predicted']} | {_cell(r['note'])} |")
    lines += ["", f"## 2. Manual checks ({len(manual)})", "", "| ID | Check | Steps |", "|---|---|---|"]
    for r in manual:
        lines.append(f"| {r['id']} | {_cell(r['title'])} | {_cell(r['how'])} |")
    lines += [
        "", f"## 3. Verified by simulation only ({len(sim_only)})", "",
        "Packet Tracer end devices cannot forge a source address or send a bare ACK, and device-originated traffic "
        "is checked on the receiving side. These scenarios therefore stay *simulation* results.", "",
        "| ID | Test | Why not testable |", "|---|---|---|",
    ]
    for r in sim_only:
        lines.append(f"| {r['id']} | {_cell(r['title'])} | {_cell(r['note'])} |")
    lines += [
        "", "## 4. Hardening checks", "",
        "The audit scenarios (L-xx, H-xx) are answered by the auditor. In Packet Tracer they are verified by exporting "
        "`show running-config` from every device and auditing the export (manual check X-07).", "",
    ]
    return "\n".join(lines)


def pt_results_template(run: ValidationRun, topology: Topology) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "simulator_predicts", "packet_tracer_result", "date", "notes", "screenshot"])
    for row in pt_plan_rows(run, topology):
        if not row["testable"]:
            continue
        predicts = "succeeds" if row["predicted"] == "succeeds" else "blocked" if row["predicted"].startswith("fails") else "manual"
        w.writerow([row["id"], predicts, "not-run", "", "", ""])
    return buf.getvalue()


def pt_compare(run: ValidationRun, results_csv: str) -> dict:
    """Compare the simulator's hardened predictions with results recorded from Packet Tracer."""
    predicted = {r.scenario.id: r.outcomes["hardened"].actual for r in run.results if r.scenario.kind == "flow"}
    rows = list(csv.DictReader(io.StringIO(results_csv)))
    agree, disagree, not_run, unsupported, unknown = [], [], [], [], []
    for row in rows:
        sid, got = row.get("id", "").strip(), (row.get("packet_tracer_result") or "not-run").strip().lower()
        if sid not in predicted:
            if not sid.startswith("X-"):
                unknown.append(sid)
            continue
        want = "succeeded" if predicted[sid] == "delivered" else "blocked"
        if got in ("", "not-run"):
            not_run.append(sid)
        elif got == "not-supported":
            unsupported.append(sid)
        elif got == want:
            agree.append(sid)
        else:
            disagree.append({"id": sid, "simulator": want, "packet_tracer": got})
    return {"agree": agree, "disagree": disagree, "not_run": not_run, "not_supported": unsupported, "unknown_ids": unknown}
