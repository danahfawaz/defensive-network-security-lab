"""Dynamic-routing rules (RTE-*): RIP and OSPF.

Which interfaces take part in a routing process is worked out the way IOS does it:
RIP ``network`` statements are classful, OSPF ``network`` statements use wildcard
masks (or ``ip ospf <pid> area <n>`` on the interface), and ``passive-interface``
statements are applied last.  EIGRP and BGP are not modelled.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..model import Severity
from ..parser import ConfigLine, DeviceConfig, Interface, canon_ifname
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG, Hit, attack, iface_evidence, rule

_MODELLED = ("rip", "ospf")


@dataclass
class Covered:
    iface: Interface
    area: str | None
    passive: bool


def _classful_network(ip: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
    first = ip.packed[0]
    prefix = 8 if first < 128 else 16 if first < 192 else 24
    return ipaddress.IPv4Network((ip, prefix), strict=False).network_address


def _passive_status(proc: ConfigLine, names: list[str]) -> dict[str, bool]:
    default = proc.child_state("passive-interface", "default")[0] is True
    status = {n: default for n in names}
    for c in proc.children:
        parts = c.text.split()
        if c.starts("passive-interface") and len(parts) >= 2 and parts[1].lower() != "default":
            status[canon_ifname(parts[1])] = True
        elif c.starts("no", "passive-interface") and len(parts) >= 3 and parts[2].lower() != "default":
            status[canon_ifname(parts[2])] = False
    return status


def covered_interfaces(cfg: DeviceConfig, proc: ConfigLine) -> list[Covered]:
    """Interfaces that run ``proc`` (``router rip`` / ``router ospf N``), with passive state."""
    kind = proc.words[1] if len(proc.words) > 1 else ""
    if kind not in _MODELLED:
        return []
    covered: list[tuple[Interface, str | None]] = []
    if kind == "rip":
        nets = set()
        for c in proc.children_starting("network"):
            try:
                nets.add(ipaddress.IPv4Address(c.words[1]))
            except (IndexError, ValueError):
                continue
        for iface in cfg.interfaces:
            if iface.ip and not iface.shutdown and _classful_network(iface.ip.ip) in nets:
                covered.append((iface, None))
    else:
        statements = []
        for c in proc.children_starting("network"):
            if len(c.words) >= 5 and c.words[3] == "area":
                try:
                    statements.append((int(ipaddress.IPv4Address(c.words[1])), int(ipaddress.IPv4Address(c.words[2])), c.words[4]))
                except ValueError:
                    continue
        pid = proc.words[2] if len(proc.words) > 2 else ""
        for iface in cfg.interfaces:
            if not iface.ip or iface.shutdown:
                continue
            area = None
            direct = iface.get("ip", "ospf", pid, "area") if pid else None
            if direct and len(direct.words) >= 5:
                area = direct.words[4]
            else:
                ip = int(iface.ip.ip)
                for addr, wild, a in statements:
                    if (ip ^ addr) & ~wild & 0xFFFFFFFF == 0:
                        area = a
                        break
            if area is not None:
                covered.append((iface, area))
    status = _passive_status(proc, [i.name for i, _ in covered])
    return [Covered(i, a, status.get(i.name, False)) for i, a in covered]


def _auth_mode(proc: ConfigLine, c: Covered) -> str:
    """none | plain | md5 | keychain for one active interface."""
    kind = proc.words[1]
    iface = c.iface
    if kind == "ospf":
        lines = iface.all("ip", "ospf", "authentication")
        if lines:
            rest = lines[-1].words[3:]
            if rest[:1] == ("message-digest",):
                return "md5"
            if rest[:1] == ("null",):
                return "none"
            if rest[:1] == ("key-chain",):
                return "keychain"
            return "plain"
        for a in proc.children_starting("area"):
            if len(a.words) >= 3 and a.words[1] == (c.area or "") and a.words[2] == "authentication":
                return "md5" if a.words[3:4] == ("message-digest",) else "plain"
        return "none"
    # RIP
    ver = proc.child_starting("version")
    if not (ver and ver.words[1:2] == ("2",)):
        return "none"  # RIPv1 has no authentication at all
    if iface.get("ip", "rip", "authentication", "key-chain") is None:
        return "none"
    mode = iface.get("ip", "rip", "authentication", "mode")
    return "md5" if mode and mode.words[4:5] == ("md5",) else "plain"


@rule(
    id="RTE-001",
    title="Routing updates are not authenticated",
    severity=Severity.HIGH,
    category="Routing",
    risk=(
        "Any host that can send packets to an interface running the protocol can inject routes - a default route or "
        "more-specific prefixes - and silently redirect, intercept or black-hole traffic."
    ),
    remediation=(
        "RIPv2: 'key chain' + 'ip rip authentication mode md5' + 'ip rip authentication key-chain'. OSPF: 'area <n> "
        "authentication message-digest' (or per-interface) with 'ip ospf message-digest-key'. Also make user-facing "
        "interfaces passive."
    ),
    references=(attack("T1557", "Adversary-in-the-Middle"), REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
)
def unauthenticated_updates(cfg: DeviceConfig):
    for proc in cfg.routing_processes:
        if proc.words[1] not in _MODELLED:
            continue
        bad = [c for c in covered_interfaces(cfg, proc) if not c.passive and _auth_mode(proc, c) == "none"]
        if bad:
            why = " RIPv1 cannot authenticate at all." if proc.words[1] == "rip" and not any(
                l.words[1:2] == ("2",) for l in proc.children_starting("version")) else ""
            yield Hit(
                obj=proc.text,
                detail=f"'{proc.text}' sends and accepts unauthenticated updates on {len(bad)} interface(s)." + why,
                evidence=[proc] + iface_evidence([c.iface for c in bad])[:7],
                affected=[c.iface.name for c in bad],
            )


@rule(
    id="RTE-002",
    title="RIP version 1 is in use",
    severity=Severity.MEDIUM,
    category="Routing",
    risk=(
        "RIPv1 is classful (updates carry no subnet masks, so VLSM designs cannot be expressed), broadcasts its updates "
        "and has no authentication, so any host on the segment can spoof a neighbour."
    ),
    remediation="'router rip' / 'version 2' / 'no auto-summary' with authentication, or migrate to OSPF.",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
)
def ripv1(cfg: DeviceConfig):
    for proc in cfg.top("router", "rip"):
        ver = proc.child_starting("version")
        if not (ver and ver.words[1:2] == ("2",)):
            yield Hit(
                obj=proc.text,
                detail="No 'version 2' under 'router rip': the process sends RIPv1 (classful) updates.",
                evidence=[proc] + ([ver] if ver else []),
            )


@rule(
    id="RTE-003",
    title="Routing protocol is active on every interface (no passive-interface)",
    severity=Severity.MEDIUM,
    category="Routing",
    risk=(
        "Without passive interfaces the router sends and accepts routing updates on user-facing segments too, so a "
        "host there can learn the topology, form adjacencies or inject routes."
    ),
    remediation=(
        "Use 'passive-interface default' under the routing process, then 'no passive-interface <link>' only on "
        "interfaces that face routers."
    ),
    references=(REF_CISCO_HARDEN, REF_NSA_NIG, REF_CIS_IOS),
)
def no_passive_interface(cfg: DeviceConfig):
    for proc in cfg.routing_processes:
        if proc.words[1] not in ("rip", "ospf", "eigrp"):
            continue
        if any(c.starts("passive-interface") for c in proc.children):
            continue
        active = [c.iface.name for c in covered_interfaces(cfg, proc) if not c.passive]
        yield Hit(
            obj=proc.text,
            detail=f"'{proc.text}' has no 'passive-interface' statement"
            + (f"; it is active on {len(active)} interface(s)." if active else "."),
            evidence=[proc],
            affected=active,
        )


@rule(
    id="RTE-004",
    title="OSPF or RIP uses plain-text authentication",
    severity=Severity.MEDIUM,
    category="Routing",
    risk=(
        "Plain-text authentication puts the key in every routing packet. Anyone who can sniff the segment learns it and "
        "can then forge updates as a trusted neighbour."
    ),
    remediation="Use MD5 (or HMAC-SHA with key chains where supported): 'ip ospf authentication message-digest'.",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
)
def plain_text_auth(cfg: DeviceConfig):
    for proc in cfg.routing_processes:
        if proc.words[1] not in _MODELLED:
            continue
        bad = [c for c in covered_interfaces(cfg, proc) if not c.passive and _auth_mode(proc, c) == "plain"]
        if bad:
            yield Hit(
                obj=proc.text,
                detail=f"'{proc.text}' uses plain-text authentication on {len(bad)} interface(s).",
                evidence=[proc] + iface_evidence([c.iface for c in bad])[:7],
                affected=[c.iface.name for c in bad],
            )
