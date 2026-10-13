"""Security validation scenarios: load them, run them against the configurations, compare with what was expected.

A scenario file (``scenarios/scenarios.yaml``) lists test cases of three kinds:

``flow``     a packet exchange judged by the policy simulator (:mod:`ciscoaudit.policy.engine`);
``audit``    an assertion about the configuration, answered by the auditor's own rules;
``manual``   a check that only Packet Tracer can answer - listed so it is not forgotten, reported as *pending*.

Every scenario states what the **hardened** configuration must do (``expect``) and, where it is informative, what the
**baseline** configuration does (``baseline``).  Asserting the baseline result as well is what turns "before and after"
from a story into a computed fact: the attack really does get through before hardening.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..audit import audit_files, select_rules
from .engine import FlowResult, Simulator
from .flow import FlowError, FlowSpec, parse_flow
from .network import Network, load_network
from .topology import STATES, Topology

SCHEMA = 1
CATEGORIES = {
    "permitted": "Business traffic that must work",
    "blocked": "Traffic that must be stopped",
    "spoofing": "Forged source addresses",
    "management": "Access to the devices themselves",
    "limitation": "Known limitations (documented, not fixed)",
    "layer2": "Switch (Layer 2) protections",
    "hygiene": "Device hardening baseline",
    "manual": "Checks only Packet Tracer can answer",
}
KINDS = ("flow", "audit", "manual")
FLOW_EXPECT = ("delivered", "blocked")
AUDIT_EXPECT = ("clean", "finding")
BLOCKERS = ("route", "vty", "no-service")  # anything else names an ACL
PHASES = ("request", "reply")
_KEYS = {"id", "title", "category", "kind", "threats", "flow", "expect", "by", "at", "phase", "baseline", "note",
         "check", "steps", "pt", "limitation"}


class ScenarioError(ValueError):
    """The scenario file is malformed."""


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    category: str
    kind: str
    threats: tuple[str, ...] = ()
    flow: FlowSpec | None = None
    expect: str = ""
    by: str | None = None
    at: str | None = None
    phase: str | None = None
    baseline: str | None = None
    note: str = ""
    check: dict[str, Any] = field(default_factory=dict)
    steps: tuple[str, ...] = ()
    pt: dict[str, str] = field(default_factory=dict)
    limitation: str = ""

    def expected(self, state: str) -> str | None:
        return self.expect if state == "hardened" else self.baseline


@dataclass
class Outcome:
    state: str
    status: str  # pass | fail | info | pending
    actual: str  # delivered | blocked | clean | finding | pending
    detail: str = ""
    blocked_by: str | None = None
    at: str | None = None
    phase: str = "-"
    trace: list[str] = field(default_factory=list)
    reply_trace: list[str] | None = None


@dataclass
class ScenarioResult:
    scenario: Scenario
    outcomes: dict[str, Outcome]

    @property
    def failed(self) -> bool:
        return any(o.status == "fail" for o in self.outcomes.values())


@dataclass
class ValidationRun:
    results: list[ScenarioResult]
    states: tuple[str, ...]
    design_ok: dict[str, bool] = field(default_factory=dict)

    def count(self, state: str, status: str) -> int:
        return sum(1 for r in self.results if r.outcomes[state].status == status)

    @property
    def failures(self) -> list[tuple[ScenarioResult, Outcome]]:
        return [(r, o) for r in self.results for o in r.outcomes.values() if o.status == "fail"]


# --------------------------------------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------------------------------------


def _text(entry: dict, key: str, where: str, *, required: bool = True) -> str:
    value = entry.get(key)
    if value is None or not str(value).strip():
        if required:
            raise ScenarioError(f"{where}: missing '{key}'")
        return ""
    return str(value).strip()


def load_scenarios(path: str | Path, topology: Topology | None = None) -> list[Scenario]:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScenarioError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("scenarios"), list):
        raise ScenarioError(f"{path}: expected 'schema: {SCHEMA}' and a 'scenarios:' list")
    out: list[Scenario] = []
    seen: set[str] = set()
    for index, entry in enumerate(data["scenarios"], 1):
        if not isinstance(entry, dict):
            raise ScenarioError(f"{p.name}#{index}: each scenario must be a mapping")
        where = f"{p.name}#{index} ({entry.get('id', '?')})"
        unknown = set(entry) - _KEYS
        if unknown:
            raise ScenarioError(f"{where}: unknown key(s) {sorted(unknown)}")
        sid = _text(entry, "id", where)
        if sid in seen:
            raise ScenarioError(f"{where}: duplicate id {sid}")
        seen.add(sid)
        category = _text(entry, "category", where)
        if category not in CATEGORIES:
            raise ScenarioError(f"{where}: category must be one of {', '.join(CATEGORIES)}")
        kind = str(entry.get("kind", "flow"))
        if kind not in KINDS:
            raise ScenarioError(f"{where}: kind must be one of {', '.join(KINDS)}")
        flow = None
        expect = str(entry.get("expect", "") or "")
        baseline = entry.get("baseline")
        if kind == "flow":
            try:
                flow = parse_flow(_text(entry, "flow", where))
            except FlowError as exc:
                raise ScenarioError(f"{where}: {exc}") from exc
            allowed = FLOW_EXPECT
        elif kind == "audit":
            check = entry.get("check")
            if not isinstance(check, dict) or not check.get("rules"):
                raise ScenarioError(f"{where}: an audit scenario needs 'check: {{rules: [...], device: ...}}'")
            allowed = AUDIT_EXPECT
            patterns = check["rules"] if isinstance(check["rules"], list) else [check["rules"]]
            try:
                select_rules([str(x) for x in patterns])
            except ValueError as exc:
                raise ScenarioError(f"{where}: {exc}") from exc
        else:
            allowed = ()
            if not entry.get("steps"):
                raise ScenarioError(f"{where}: a manual scenario needs 'steps'")
        if kind != "manual":
            if expect not in allowed:
                raise ScenarioError(f"{where}: expect must be one of {', '.join(allowed)}")
            if baseline is not None and baseline not in allowed:
                raise ScenarioError(f"{where}: baseline must be one of {', '.join(allowed)}")
        by, at, phase = entry.get("by"), entry.get("at"), entry.get("phase")
        if (by or at or phase) and not (kind == "flow" and expect == "blocked"):
            raise ScenarioError(f"{where}: 'by', 'at' and 'phase' only make sense for a flow that is expected to be blocked")
        if phase is not None and phase not in PHASES:
            raise ScenarioError(f"{where}: phase must be one of {', '.join(PHASES)}")
        if category == "limitation" and not str(entry.get("limitation", "")).strip():
            raise ScenarioError(f"{where}: a limitation scenario must say which limitation it documents ('limitation:')")
        if topology is not None and flow is not None:
            _check_names(flow, topology, where)
        out.append(Scenario(
            id=sid, title=_text(entry, "title", where), category=category, kind=kind,
            threats=tuple(str(t) for t in entry.get("threats", ())), flow=flow, expect=expect,
            by=str(by) if by else None, at=str(at) if at else None, phase=str(phase) if phase else None,
            baseline=str(baseline) if baseline else None, note=str(entry.get("note", "")).strip(),
            check=dict(entry.get("check") or {}), steps=tuple(str(s) for s in entry.get("steps", ())),
            pt={str(k): str(v) for k, v in (entry.get("pt") or {}).items()},
            limitation=str(entry.get("limitation", "")).strip(),
        ))
    return out


def _check_names(flow: FlowSpec, topology: Topology, where: str) -> None:
    known = set(topology.hosts) | set(topology.devices)
    for name in (flow.src, flow.dst):
        if name in known:
            continue
        try:
            import ipaddress

            ipaddress.IPv4Address(name)
        except ValueError:
            raise ScenarioError(f"{where}: {name!r} is not a host, a device or an IPv4 address of the topology") from None
    if flow.src in topology.devices and not topology.devices[flow.src].audited:
        raise ScenarioError(f"{where}: {flow.src} is test infrastructure; use a host as the sender")


# --------------------------------------------------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------------------------------------------------


class _Runner:
    def __init__(self, topology: Topology) -> None:
        self.topology = topology
        self._networks: dict[str, Network] = {}
        self._sims: dict[str, Simulator] = {}
        self._audits: dict[str, Any] = {}

    def sim(self, state: str) -> Simulator:
        if state not in self._sims:
            self._networks[state] = load_network(self.topology, state)
            self._sims[state] = Simulator(self._networks[state])
        return self._sims[state]

    def audit(self, state: str):
        if state not in self._audits:
            self._audits[state] = audit_files([self.topology.root / "configs" / state])
        return self._audits[state]

    # -- one scenario in one state -----------------------------------------------------------------------------------
    def run(self, sc: Scenario, state: str) -> Outcome:
        if sc.kind == "manual":
            return Outcome(state, "pending", "pending", "needs a Packet Tracer run (see the test plan)")
        expected = sc.expected(state)
        if sc.kind == "flow":
            return self._flow(sc, state, expected)
        return self._audit(sc, state, expected)

    def _flow(self, sc: Scenario, state: str, expected: str | None) -> Outcome:
        assert sc.flow is not None
        result: FlowResult = self.sim(state).run(sc.flow)
        actual = "delivered" if result.delivered else "blocked"
        out = Outcome(state, "info", actual, result.summary(), result.blocked_by, result.at, result.phase,
                      [str(h) for h in result.forward.hops],
                      [str(h) for h in result.reply.hops] if result.reply is not None else None)
        if expected is None:
            return out
        problems = []
        if actual != expected:
            problems.append(f"expected {expected} but the simulator says {actual} ({result.summary()})")
        elif expected == "blocked" and state == "hardened":
            if sc.by and result.blocked_by != sc.by:
                problems.append(f"expected to be stopped by {sc.by}, but it was stopped by {result.blocked_by or 'nothing'}")
            if sc.at and result.at != sc.at:
                problems.append(f"expected to stop at {sc.at}, but it stopped at {result.at or 'nowhere'}")
            if sc.phase and result.phase != sc.phase:
                problems.append(f"expected the {sc.phase} to be stopped, but it was the {result.phase}")
        out.status = "fail" if problems else "pass"
        if problems:
            out.detail = "; ".join(problems)
        return out

    def _audit(self, sc: Scenario, state: str, expected: str | None) -> Outcome:
        patterns = sc.check["rules"]
        patterns = [patterns] if isinstance(patterns, str) else list(patterns)
        devices = sc.check.get("device", "*")
        devices = [devices] if isinstance(devices, str) else list(devices)
        import fnmatch

        wanted = {r.id for r in select_rules(patterns)}
        hits = [f for f in self.audit(state).findings
                if f.rule_id in wanted and any(fnmatch.fnmatchcase(f.device, d) for d in devices)]
        actual = "finding" if hits else "clean"
        if hits:
            detail = "; ".join(sorted({f"{f.rule_id} on {f.device}: {f.title}" for f in hits}))
        else:
            detail = f"no findings from {', '.join(sorted(wanted))} on {', '.join(devices)}"
        out = Outcome(state, "info", actual, detail)
        if expected is not None:
            out.status = "pass" if actual == expected else "fail"
            if out.status == "fail":
                out.detail = f"expected {expected} but the auditor reports {actual}: {detail}"
        return out


def run_scenarios(topology: Topology, scenarios: list[Scenario], states: tuple[str, ...] = STATES) -> ValidationRun:
    from .design import check_design

    runner = _Runner(topology)
    results = [ScenarioResult(sc, {state: runner.run(sc, state) for state in states}) for sc in scenarios]
    design = {state: not any(i.severity == "error" for i in check_design(topology, state)) for state in states}
    return ValidationRun(results, tuple(states), design)
