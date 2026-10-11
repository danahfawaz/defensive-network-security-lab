"""Layer-2 switch hardening rules (L2-*)."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import Severity
from ..parser import ConfigLine, DeviceConfig, Interface
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG, Hit, attack, iface_evidence, rule

_PORT_TYPES = ("fastethernet", "gigabitethernet", "tengigabitethernet", "ethernet")
_EDGE_MODES = ("access", "dynamic-auto", "dynamic-desirable")
_NEUTRAL_FIRST_WORDS = {"duplex", "speed", "negotiation", "mdix", "flowcontrol"}


@dataclass
class Port:
    iface: Interface
    mode: str  # access | trunk | dynamic-auto | dynamic-desirable | other

    @property
    def name(self) -> str:
        return self.iface.name

    @property
    def up(self) -> bool:
        return not self.iface.shutdown

    @property
    def edge_capable(self) -> bool:
        return self.mode in _EDGE_MODES


def ports(cfg: DeviceConfig) -> list[Port]:
    """Layer-2 ports: physical interfaces that are not routed; unset mode is IOS's default (dynamic auto)."""
    result = []
    for iface in cfg.interfaces:
        if iface.kind != "physical" or not iface.name.lower().startswith(_PORT_TYPES):
            continue
        mode = iface.explicit_mode
        if mode == "routed" or (mode is None and iface.ip is not None):
            continue
        result.append(Port(iface, mode or "dynamic-auto"))
    return result


def _exact(iface: Interface, *words: str) -> bool | None:
    """Last exact statement of ``words`` (True) or its 'no' form (False); None if never configured."""
    state: bool | None = None
    for c in iface.commands:
        if c.words == tuple(words):
            state = True
        elif c.words == ("no",) + tuple(words):
            state = False
    return state


def _portfast(cfg: DeviceConfig, port: Port) -> bool:
    explicit: bool | None = None
    for c in port.iface.all("spanning-tree", "portfast"):
        if "disable" in c.words:
            explicit = False
        elif c.words[2:] in ((), ("edge",)):
            explicit = True
    if explicit is not None:
        return explicit
    return bool(
        port.mode == "access"
        and (cfg.state("spanning-tree", "portfast", "default")[0] or cfg.state("spanning-tree", "portfast", "edge", "default")[0])
    )


def _bpduguard(cfg: DeviceConfig, port: Port, portfast: bool) -> bool:
    explicit: bool | None = None
    for c in port.iface.all("spanning-tree", "bpduguard"):
        if c.words[2:3] == ("enable",):
            explicit = True
        elif c.words[2:3] == ("disable",):
            explicit = False
    if explicit is not None:
        return explicit
    global_default = any(
        l.starts("spanning-tree", "portfast") and "bpduguard" in l.words and "default" in l.words for l in cfg.lines
    )
    return portfast and global_default


def _summary(items: list[Port], limit: int = 5) -> str:
    names = [p.name for p in items]
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


@rule(
    id="L2-001",
    title="Switch ports negotiate trunking (DTP dynamic mode)",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk=(
        "A port left in dynamic auto/desirable mode will turn itself into an 802.1Q trunk if the device on the other end "
        "asks it to. An attacker's host (or a rogue switch) then receives every VLAN the trunk carries."
    ),
    remediation="Set 'switchport mode access' on every end-user port and 'switchport mode trunk' + 'switchport nonegotiate' on uplinks.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
    applies_to=("switch",),
)
def dtp_dynamic(cfg: DeviceConfig):
    bad = [p for p in ports(cfg) if p.up and p.mode in ("dynamic-auto", "dynamic-desirable")]
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} enabled port(s) are in dynamic mode: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-002",
    title="Trunk ports still send DTP frames",
    severity=Severity.LOW,
    category="Layer 2",
    risk="A static trunk without 'switchport nonegotiate' keeps advertising DTP, which leaks the link's role and invites negotiation attempts.",
    remediation="Add 'switchport nonegotiate' to every static trunk.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS),
    applies_to=("switch",),
)
def trunk_negotiates(cfg: DeviceConfig):
    bad = [p for p in ports(cfg) if p.up and p.mode == "trunk" and _exact(p.iface, "switchport", "nonegotiate") is not True]
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} trunk(s) lack 'switchport nonegotiate': {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-003",
    title="Trunk native VLAN is the default VLAN 1",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk=(
        "Native-VLAN frames cross a trunk untagged. A host in the native VLAN can double-tag frames so that the first "
        "switch strips the outer tag and the second delivers the packet into another VLAN (VLAN hopping)."
    ),
    remediation="Use an unused VLAN as native VLAN on every trunk: 'switchport trunk native vlan 999' (no ports or SVI in it).",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
    applies_to=("switch",),
)
def native_vlan_default(cfg: DeviceConfig):
    bad = []
    for p in ports(cfg):
        if not (p.up and p.mode == "trunk"):
            continue
        line = p.iface.get("switchport", "trunk", "native", "vlan")
        if line is None or line.words[4:5] == ("1",):
            bad.append(p)
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} trunk(s) use native VLAN 1: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-004",
    title="Trunk carries every VLAN",
    severity=Severity.LOW,
    category="Layer 2",
    risk="A trunk that allows all VLANs widens broadcast domains and extends the reach of VLAN-hopping and spanning-tree attacks to VLANs that do not belong on that link.",
    remediation="Prune each trunk: 'switchport trunk allowed vlan 10,20,99'.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS),
    applies_to=("switch",),
)
def trunk_allows_all(cfg: DeviceConfig):
    bad = []
    for p in ports(cfg):
        if not (p.up and p.mode == "trunk"):
            continue
        line = p.iface.get("switchport", "trunk", "allowed", "vlan")
        if line is None or line.words[4:5] == ("all",):
            bad.append(p)
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} trunk(s) allow all VLANs: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-005",
    title="Port security is not enabled on edge ports",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk=(
        "Without port security anyone can plug an unknown device into a live port, or flood the switch with spoofed "
        "source MACs until its CAM table overflows and it forwards traffic like a hub, exposing other users' frames."
    ),
    remediation=(
        "On access ports: 'switchport mode access', 'switchport port-security', 'switchport port-security maximum 2', "
        "'switchport port-security mac-address sticky', 'switchport port-security violation restrict' (or shutdown)."
    ),
    references=(attack("T1200", "Hardware Additions"), attack("T1557", "Adversary-in-the-Middle"), REF_CISCO_HARDEN, REF_CIS_IOS),
    applies_to=("switch",),
)
def no_port_security(cfg: DeviceConfig):
    bad = [p for p in ports(cfg) if p.up and p.edge_capable and _exact(p.iface, "switchport", "port-security") is not True]
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} edge-capable port(s) lack port security: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-006",
    title="PortFast with BPDU Guard is missing on edge ports",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk=(
        "A switch (or a host running a bridging tool) plugged into an edge port can send BPDUs, win the root-bridge "
        "election and pull traffic through itself, or trigger repeated reconvergence and an outage."
    ),
    remediation="'spanning-tree portfast' + 'spanning-tree bpduguard enable' per port, or 'spanning-tree portfast default' + 'spanning-tree portfast bpduguard default' globally.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
    applies_to=("switch",),
)
def no_bpduguard(cfg: DeviceConfig):
    bad = []
    for p in ports(cfg):
        if not (p.up and p.edge_capable):
            continue
        pf = _portfast(cfg, p)
        if not (pf and _bpduguard(cfg, p, pf)):
            bad.append(p)
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} edge-capable port(s) lack PortFast + BPDU Guard: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-007",
    title="Unused ports are enabled",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk="A live, unconfigured port is an open door for anyone with physical access: plug in and you are on the network (usually in VLAN 1).",
    remediation="'shutdown' every unused port and park it in an unused VLAN ('switchport access vlan 999').",
    references=(attack("T1200", "Hardware Additions"), REF_CIS_IOS, REF_NSA_NIG),
    applies_to=("switch",),
)
def unused_ports_enabled(cfg: DeviceConfig):
    def untouched(iface: Interface) -> bool:
        for c in iface.commands:
            if c.words == ("no", "shutdown") or c.words[0] in _NEUTRAL_FIRST_WORDS:
                continue
            return False
        return True

    bad = [p for p in ports(cfg) if p.up and untouched(p.iface)]
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} port(s) are up with default configuration: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-008",
    title="Active ports use the default VLAN 1",
    severity=Severity.MEDIUM,
    category="Layer 2",
    risk=(
        "VLAN 1 cannot be deleted and carries control-plane protocols (CDP, VTP, DTP, STP). Placing users there removes "
        "any segmentation and exposes those protocols to them."
    ),
    remediation="Assign end-user ports to purpose-built VLANs ('switchport access vlan 10') and keep VLAN 1 empty.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
    applies_to=("switch",),
)
def vlan1_in_use(cfg: DeviceConfig):
    bad = []
    for p in ports(cfg):
        if not (p.up and p.edge_capable):
            continue
        line = p.iface.get("switchport", "access", "vlan")
        if line is None or line.words[3:4] == ("1",):
            bad.append(p)
    if bad:
        yield Hit(obj="interfaces", detail=f"{len(bad)} active port(s) are in VLAN 1: {_summary(bad)}.",
                  evidence=iface_evidence([p.iface for p in bad])[:8], affected=[p.name for p in bad])


@rule(
    id="L2-009",
    title="Management address sits in VLAN 1",
    severity=Severity.LOW,
    category="Layer 2",
    risk="Managing the switch from VLAN 1 mixes management with the default VLAN that every unconfigured port belongs to.",
    remediation="Move the management SVI to a dedicated management VLAN ('interface Vlan99') and shut down 'interface Vlan1'.",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
    applies_to=("switch",),
)
def mgmt_in_vlan1(cfg: DeviceConfig):
    svi = cfg.interface("Vlan1")
    if svi and svi.ip and not svi.shutdown:
        yield Hit(obj="interface Vlan1", detail=f"'interface Vlan1' carries {svi.ip.ip} and is up.", evidence=[svi.line])


@rule(
    id="L2-010",
    title="VTP is not in transparent or off mode",
    severity=Severity.LOW,
    category="Layer 2",
    risk=(
        "In VTP server or client mode, a switch advertising a higher revision number overwrites the VLAN database of "
        "every switch in the domain - by accident or on purpose - deleting VLANs and causing an outage."
    ),
    remediation="'vtp mode transparent' (or 'vtp mode off' where supported) and manage VLANs per switch.",
    references=(REF_CISCO_HARDEN, REF_CIS_IOS),
    applies_to=("switch",),
)
def vtp_not_transparent(cfg: DeviceConfig):
    for line in cfg.top("vtp", "mode"):
        if line.words[2:3] in (("transparent",), ("off",)):
            return
    yield Hit(obj="global", detail="No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).")
