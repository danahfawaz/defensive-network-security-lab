"""Exhaustive reachability matrix, checked against the written policy.

Hand-picked scenarios show that chosen attacks fail; they cannot show that *nothing else* gets through.  The matrix probes
every sender against every destination for a fixed list of services, asks the policy simulator what the configuration does
with each probe, and compares the answer with ``topology/policy-intent.yaml`` - a short list of the flows the organisation
actually wants.  Two kinds of disagreement are reported:

* **unexpected permit**: the *request* of a flow the policy does not list reaches its destination (a hole - even if the
  reply is dropped, because blind and one-way attacks do not need the reply);
* **unexpected block**: a flow the policy lists does not work as a round trip (a broken service).

Probing unused addresses next to each server catches rules that are written for a whole subnet when one host was meant.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .engine import Simulator
from .flow import FlowSpec
from .network import load_network
from .topology import Topology

SCHEMA = 1
DEFAULT_SERVICES = {
    "icmp": "icmp/echo", "ssh": "tcp/22", "telnet": "tcp/23", "http": "tcp/80", "https": "tcp/443", "rdp": "tcp/3389",
    "smb": "tcp/445", "dns-udp": "udp/53", "dns-tcp": "tcp/53", "syslog": "udp/514", "snmp": "udp/161",
}


class IntentError(ValueError):
    """The policy-intent file is malformed."""


@dataclass(frozen=True)
class Rule:
    senders: tuple[str, ...]
    destinations: tuple[str, ...]
    services: tuple[str, ...]
    why: str


@dataclass
class Intent:
    services: dict[str, str]
    destinations: dict[str, str]  # extra probed addresses: name -> IPv4 (aliases of device interfaces, unused addresses)
    rules: list[Rule]
    intra_zone: str = "allow"
    path: Path | None = None


@dataclass(frozen=True)
class Cell:
    sender: str
    destination: str
    service: str
    delivered: bool  # the request reaches the destination
    intended: bool
    intra_zone: bool = False
    round_trip: bool = False  # ...and the reply comes back
    blocked_by: str | None = None
    at: str | None = None
    phase: str = "-"
    why: str = ""

    @property
    def violation(self) -> str | None:
        if self.delivered and not self.intended:
            return "unexpected permit"
        if self.intended and not self.round_trip:
            return "unexpected block"
        return None


@dataclass
class Matrix:
    state: str
    senders: list[str]
    destinations: list[str]
    services: list[str]
    cells: list[Cell] = field(default_factory=list)

    @property
    def violations(self) -> list[Cell]:
        return [c for c in self.cells if c.violation]

    @property
    def permitted(self) -> list[Cell]:
        return [c for c in self.cells if c.delivered]

    @property
    def cross_zone_permitted(self) -> list[Cell]:
        return [c for c in self.cells if c.delivered and not c.intra_zone]


# --------------------------------------------------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def load_intent(path: str | Path, topology: Topology) -> Intent:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise IntentError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise IntentError(f"{path}: expected 'schema: {SCHEMA}'")
    services = {str(k): str(v) for k, v in (data.get("services") or DEFAULT_SERVICES).items()}
    destinations = {str(k): str(v) for k, v in (data.get("destinations") or {}).items()}
    known = set(topology.hosts) | set(topology.zones) | set(topology.management) | set(destinations)
    clash = (set(topology.hosts) | set(topology.zones) | set(topology.management)) & set(destinations)
    if clash:
        raise IntentError(f"{path}: destination names clash with hosts, zones or devices: {sorted(clash)}")
    rules = []
    for index, entry in enumerate(data.get("allow") or [], 1):
        where = f"{p.name}: allow[{index}]"
        if not isinstance(entry, dict) or not {"from", "to", "services", "why"} <= set(entry):
            raise IntentError(f"{where}: needs from, to, services and why")
        senders, dests, svcs = _as_list(entry["from"]), _as_list(entry["to"]), _as_list(entry["services"])
        if not str(entry["why"]).strip():
            raise IntentError(f"{where}: 'why' must explain the business need")
        for name in senders + dests:
            if name not in known:
                raise IntentError(f"{where}: unknown host, zone, device or destination {name!r}")
        for s in svcs:
            if s not in services:
                raise IntentError(f"{where}: unknown service {s!r}; defined: {', '.join(services)}")
        rules.append(Rule(tuple(senders), tuple(dests), tuple(svcs), str(entry["why"]).strip()))
    return Intent(services, destinations, rules, str(data.get("intra_zone", "allow")), p)


# --------------------------------------------------------------------------------------------------------------------
# computing
# --------------------------------------------------------------------------------------------------------------------


def _expand(names: tuple[str, ...], topology: Topology) -> set[str]:
    out: set[str] = set()
    for n in names:
        if n in topology.zones:
            out |= {h.name for h in topology.hosts.values() if h.zone == n}
        else:
            out.add(n)
    return out


def compute(topology: Topology, state: str, intent: Intent) -> Matrix:
    sim = Simulator(load_network(topology, state))
    senders = list(topology.hosts)
    destinations = list(topology.hosts) + [d for d in topology.management] + list(intent.destinations)
    services = list(intent.services)
    allowed: dict[tuple[str, str], dict[str, str]] = {}
    for rule in intent.rules:
        for s in _expand(rule.senders, topology):
            for d in _expand(rule.destinations, topology):
                for svc in rule.services:
                    allowed.setdefault((s, d), {})[svc] = rule.why
    matrix = Matrix(state, senders, destinations, services)
    for s in senders:
        sender_zone = topology.hosts[s].zone
        for d in destinations:
            if d == s:
                continue
            dst_ip = intent.destinations.get(d)
            if d in topology.hosts:
                dest_zone = topology.hosts[d].zone
            elif dst_ip and not sim.is_router_address(dst_ip):
                zone = topology.zone_of(dst_ip)  # an unused address beside a server: still switched inside its VLAN
                dest_zone = zone.name if zone else None
            else:
                dest_zone = None
            for svc, flow_text in intent.services.items():
                proto, _, port = flow_text.partition("/")
                flow = FlowSpec(s, dst_ip or d, proto, int(port) if proto != "icmp" else None,
                                icmp_type="echo" if proto == "icmp" else None)
                result = sim.run(flow)
                same_zone = dest_zone is not None and dest_zone == sender_zone and intent.intra_zone == "allow"
                reason = allowed.get((s, d), {}).get(svc, "")
                intended = same_zone or bool(reason)
                if same_zone and not reason:
                    reason = "same VLAN: switched, never filtered (docs/limitations.md)"
                matrix.cells.append(Cell(s, d, svc, result.forward.delivered, intended, same_zone, round_trip=result.delivered,
                                         blocked_by=result.blocked_by, at=result.at, phase=result.phase, why=reason))
    return matrix


# --------------------------------------------------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------------------------------------------------


def _short(services: list[str]) -> str:
    return " ".join(services) if services else "-"


def summary(matrix: Matrix) -> dict:
    cross = matrix.cross_zone_permitted
    return {
        "state": matrix.state, "probes": len(matrix.cells), "permitted": len(matrix.permitted),
        "permitted_between_zones": len(cross), "permitted_inside_a_zone": len(matrix.permitted) - len(cross),
        "blocked": len(matrix.cells) - len(matrix.permitted),
        "unexpected_permits": sum(1 for c in matrix.cells if c.violation == "unexpected permit"),
        "unexpected_blocks": sum(1 for c in matrix.cells if c.violation == "unexpected block"),
    }


def to_text(matrices: list[Matrix]) -> str:
    lines = []
    for m in matrices:
        s = summary(m)
        lines.append(f"{m.state}: {s['probes']} probes ({len(m.senders)} senders x {len(m.destinations)} destinations x "
                     f"{len(m.services)} services); permitted {s['permitted']} "
                     f"({s['permitted_between_zones']} between zones, {s['permitted_inside_a_zone']} inside a zone); "
                     f"unexpected permits {s['unexpected_permits']}, unexpected blocks {s['unexpected_blocks']}")
        for c in m.violations[:40]:
            lines.append(f"  {c.violation:17} {c.sender} -> {c.destination} {c.service}"
                         + (f"  (stopped by {c.blocked_by} @ {c.at}, {c.phase})" if c.blocked_by else ""))
        if len(m.violations) > 40:
            lines.append(f"  ... and {len(m.violations) - 40} more")
    return "\n".join(lines) + "\n"


def to_markdown(matrices: list[Matrix], topology: Topology, intent: Intent, *, title: str = "Reachability matrix") -> str:
    lines = [f"# {title}", "",
             "> Computed offline by the policy simulator from the configuration files, then compared with the written policy in "
             "`topology/policy-intent.yaml`. These are not Packet Tracer results.", "",
             "Every sender is probed against every destination for each of the services "
             f"({', '.join(f'`{k}`={v}' for k, v in intent.services.items())}). A probe counts as *permitted* if the "
             "request reaches its destination (a hole is a hole even when the reply is dropped); the policy's own flows must "
             "also work as a round trip. Unused addresses beside each server are probed too, so a rule "
             "written for a whole subnet shows up as a permit that the policy does not list.", "",
             "## Summary", "",
             "| | " + " | ".join(m.state for m in matrices) + " |", "|---|" + "---:|" * len(matrices)]
    sums = [summary(m) for m in matrices]
    for label, key in (("Probes", "probes"), ("Permitted", "permitted"), ("- between zones", "permitted_between_zones"),
                       ("- inside one zone (switched, never filtered)", "permitted_inside_a_zone"), ("Blocked", "blocked"),
                       ("**Unexpected permits** (holes)", "unexpected_permits"), ("**Unexpected blocks** (broken services)", "unexpected_blocks")):
        lines.append(f"| {label} | " + " | ".join(str(s[key]) for s in sums) + " |")
    lines.append("")
    for m in matrices:
        lines += [f"## {m.state.capitalize()} configuration", ""]
        if m.violations:
            lines += [f"### Disagreements with the policy ({len(m.violations)})", "",
                      "| Kind | From | To | Service | Stopped by |", "|---|---|---|---|---|"]
            for c in m.violations:
                lines.append(f"| {c.violation} | {c.sender} | {c.destination} | {c.service} | {f'{c.blocked_by} @ {c.at}' if c.blocked_by else '-'} |")
            lines.append("")
        else:
            lines += ["**No disagreements: every permitted flow is in the written policy and every listed flow works.**", ""]
        lines += ["### Permitted flows between zones", "", "| From | To | Services | Why |", "|---|---|---|---|"]
        grouped: dict[tuple[str, str], list[Cell]] = {}
        for c in m.cross_zone_permitted:
            grouped.setdefault((c.sender, c.destination), []).append(c)
        for (s, d), cells in grouped.items():
            reason = next((c.why for c in cells if c.why), "not in the policy")
            names = [c.service if c.round_trip else f"{c.service} (request only)" for c in cells]
            lines.append(f"| {s} | {d} | {_short(names)} | {reason.replace('|', '/')} |")
        lines.append("")
    return "\n".join(lines)


def to_csv(matrices: list[Matrix], *, everything: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["state", "from", "to", "service", "result", "in_policy", "intra_zone", "stopped_by", "at", "phase", "disagreement"])
    for m in matrices:
        for c in m.cells:
            if everything or c.delivered or c.violation:
                w.writerow([m.state, c.sender, c.destination, c.service, "permitted" if c.delivered else "blocked",
                            "yes" if c.intended else "no", "yes" if c.intra_zone else "no", c.blocked_by or "", c.at or "",
                            c.phase if not c.delivered else "", c.violation or ""])
    return buf.getvalue()


def to_json(matrices: list[Matrix]) -> str:
    return json.dumps({"matrices": [{"summary": summary(m), "disagreements": [
        {"kind": c.violation, "from": c.sender, "to": c.destination, "service": c.service, "stopped_by": c.blocked_by, "at": c.at}
        for c in m.violations]} for m in matrices]}, indent=2) + "\n"
