"""Unneeded services, information leaks and interface hygiene (SVC-*, INT-*)."""

from __future__ import annotations

from ..model import Severity
from ..parser import DeviceConfig
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG, Hit, attack, iface_evidence, rule

_DEFAULT_HOSTNAMES = {"router", "switch"}

_LEGACY_SERVICES = (
    ("service", "tcp-small-servers"),
    ("service", "udp-small-servers"),
    ("service", "finger"),
    ("ip", "finger"),
    ("ip", "bootp", "server"),
    ("service", "pad"),
    ("service", "config"),
    ("ip", "rcmd", "rcp-enable"),
    ("ip", "rcmd", "rsh-enable"),
    ("ip", "identd"),
    ("boot", "network"),
)


@rule(
    id="SVC-001",
    title="CDP is running",
    severity=Severity.LOW,
    category="Services",
    risk=(
        "CDP advertises the model, IOS version, interface names and management addresses to anything on the link, in "
        "clear text and without authentication. Attackers use it for reconnaissance, and CDP parsers have been affected "
        "by remotely exploitable bugs. The exposure matters most on ports that face users."
    ),
    remediation="'no cdp run' globally, or 'no cdp enable' on every interface that does not face a trusted neighbour.",
    references=(attack("T1016", "System Network Configuration Discovery"), REF_CIS_IOS, REF_NSA_NIG),
)
def cdp_enabled(cfg: DeviceConfig):
    state, _line = cfg.state("cdp", "run")
    if state is False:
        return
    ports = [i for i in cfg.interfaces if i.kind == "physical" and not i.shutdown]
    exposed = [i for i in ports if i.state("cdp", "enable")[0] is not False]
    if ports and not exposed:
        return
    yield Hit(
        obj="cdp",
        detail="CDP is globally enabled (no 'no cdp run')"
        + (f" and active on {len(exposed)} up interface(s)." if exposed else "."),
        evidence=iface_evidence(exposed)[:8],
        affected=[i.name for i in exposed],
    )


@rule(
    id="SVC-002",
    title="IP source routing is enabled",
    severity=Severity.LOW,
    category="Services",
    risk=(
        "Source-routed packets let the sender dictate the path they take, which can bypass routing-based controls and "
        "help spoofing or firewall evasion."
    ),
    remediation="'no ip source-route'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
    applies_to=("router",),
)
def source_route(cfg: DeviceConfig):
    state, _line = cfg.state("ip", "source-route")
    if state is not False:
        yield Hit(obj="global", detail="'no ip source-route' is not configured (IOS processes source-routed packets by default).")


@rule(
    id="SVC-003",
    title="Legacy or unneeded services are enabled",
    severity=Severity.MEDIUM,
    category="Services",
    risk=(
        "Small servers, finger, BOOTP, PAD, remote copy/shell and similar services add network-reachable attack surface "
        "that a modern network never needs; several are classic reconnaissance or denial-of-service targets."
    ),
    remediation="Disable each one explicitly, e.g. 'no service tcp-small-servers', 'no service udp-small-servers', 'no ip bootp server'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
)
def legacy_services(cfg: DeviceConfig):
    lines = []
    for prefix in _LEGACY_SERVICES:
        state, line = cfg.state(*prefix)
        if state:
            lines.append(line)
    if lines:
        yield Hit(obj="services", detail="Enabled: " + ", ".join(f"'{l.text}'" for l in lines) + ".",
                  evidence=lines, affected=[l.text for l in lines])


@rule(
    id="SVC-004",
    title="Device still uses the default hostname",
    severity=Severity.LOW,
    category="Services",
    risk=(
        "Devices called 'Router' or 'Switch' cannot be told apart in syslog, SNMP traps, SSH host-key warnings or change "
        "records, which makes incident response and change control error-prone."
    ),
    remediation="Give every device a unique, role-based name: 'hostname HQ-EDGE'.",
    references=(REF_CIS_IOS,),
)
def default_hostname(cfg: DeviceConfig):
    if cfg.hostname is None or cfg.hostname.lower() in _DEFAULT_HOSTNAMES:
        line = cfg.top_one("hostname")
        yield Hit(obj="global", detail=f"Hostname is {'missing' if cfg.hostname is None else repr(cfg.hostname)}.",
                  evidence=[line] if line else [])


@rule(
    id="INT-001",
    title="Proxy ARP is enabled on routed interfaces",
    severity=Severity.LOW,
    category="Interfaces",
    risk=(
        "With proxy ARP the router answers ARP requests on behalf of other subnets. This masks misconfigured masks, lets "
        "hosts without a gateway reach other segments through the router, and widens the effect of ARP spoofing."
    ),
    remediation="'no ip proxy-arp' on every routed interface or subinterface.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
    applies_to=("router",),
)
def proxy_arp(cfg: DeviceConfig):
    bad = [i for i in cfg.interfaces
           if i.kind in ("physical", "subinterface") and i.ip and not i.shutdown
           and i.state("ip", "proxy-arp")[0] is not False]
    if bad:
        yield Hit(obj="interfaces", detail=f"Proxy ARP is active (default) on {len(bad)} routed interface(s).",
                  evidence=iface_evidence(bad)[:8], affected=[i.name for i in bad])


@rule(
    id="INT-002",
    title="Directed broadcasts are forwarded",
    severity=Severity.MEDIUM,
    category="Interfaces",
    risk=(
        "A packet sent to a subnet's directed-broadcast address is turned into a link-layer broadcast, so one spoofed "
        "ICMP echo makes every host answer the victim (a smurf amplification attack)."
    ),
    remediation="'no ip directed-broadcast' on every interface.",
    references=(attack("T1498", "Network Denial of Service"), REF_CIS_IOS),
)
def directed_broadcast(cfg: DeviceConfig):
    bad = [(i, i.get("ip", "directed-broadcast")) for i in cfg.interfaces if i.get("ip", "directed-broadcast")]
    if bad:
        yield Hit(obj="interfaces", detail=f"'ip directed-broadcast' is enabled on {len(bad)} interface(s).",
                  evidence=[line for _, line in bad][:8], affected=[i.name for i, _ in bad])
