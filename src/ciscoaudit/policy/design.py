"""Design-consistency checker: do the device configurations implement ``topology/topology.yaml``?

The configurations are written by hand, so a typo in a VLAN id, a mask or an ACL name would otherwise only show up when a
test fails in Packet Tracer.  Every check here compares one fact in the configurations with the topology and reports a
precise message.  Checks marked *hardened* encode security intent and only run for the hardened configurations; the
baseline is allowed to be sloppy about security, but it must still be a working network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..acl import Packet
from ..parser import ConfigLine, DeviceConfig
from .network import Network, RouterInterface, RouterModel, SwitchModel, load_network
from .topology import Topology, TopologyError

IPv4 = ipaddress.IPv4Address


@dataclass(frozen=True)
class Issue:
    code: str
    device: str
    message: str
    severity: str = "error"  # error | warning

    def __str__(self) -> str:
        return f"{self.severity.upper():7} {self.code} {self.device}: {self.message}"


# --------------------------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------------------------


def _firewall(topo: Topology) -> str:
    names = [n for n, d in topo.devices.items() if d.kind == "router" and d.audited]
    if len(names) != 1:
        raise TopologyError(f"exactly one audited router (the firewall) is expected, found {names}")
    return names[0]


def _upstream(topo: Topology) -> str:
    names = [n for n, d in topo.devices.items() if d.kind == "router" and not d.audited]
    if len(names) != 1:
        raise TopologyError(f"exactly one non-audited router (the ISP) is expected, found {names}")
    return names[0]


def _zone_by_vlan(topo: Topology, vlan: int):
    return next((z for z in topo.zones.values() if z.vlan == vlan), None)


def _logging_hosts(cfg: DeviceConfig) -> set[str]:
    hosts = set()
    for line in cfg.top("logging"):
        words = line.words
        if len(words) >= 3 and words[1] == "host":
            hosts.add(words[2])
        elif len(words) == 2:
            hosts.add(words[1])
    return hosts


def _ntp_servers(cfg: DeviceConfig) -> set[str]:
    return {l.words[2] for l in cfg.top("ntp", "server") if len(l.words) >= 3}


def _dhcp_pools(cfg: DeviceConfig) -> list[tuple[ipaddress.IPv4Network, ConfigLine]]:
    pools = []
    for line in cfg.top("ip", "dhcp", "pool"):
        net = line.child_starting("network")
        if net and len(net.words) >= 3:
            try:
                pools.append((ipaddress.IPv4Network(f"{net.words[1]}/{net.words[2]}", strict=False), line))
            except ValueError:
                continue
    return pools


def _excluded(cfg: DeviceConfig) -> list[tuple[IPv4, IPv4]]:
    out = []
    for line in cfg.top("ip", "dhcp", "excluded-address"):
        try:
            first = IPv4(line.words[3])
            last = IPv4(line.words[4]) if len(line.words) > 4 else first
        except (IndexError, ValueError):
            continue
        out.append((first, last))
    return out


# --------------------------------------------------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------------------------------------------------


def _check_identity(net: Network, issues: list[Issue]) -> None:
    for name, spec in net.topology.devices.items():
        cfg = net.device(name).cfg
        if cfg.hostname != name:
            issues.append(Issue("D-01", name, f"hostname is {cfg.hostname!r}, the topology calls this device {name!r}"))
        if cfg.device_type != spec.kind:
            issues.append(Issue("D-01", name, f"detected as a {cfg.device_type}, the topology says {spec.kind}"))
        for w in cfg.warnings:
            issues.append(Issue("D-01", name, f"parser warning: {w}", "warning"))
    for r in net.routers.values():
        for note in r.notes:
            issues.append(Issue("D-01", r.name, f"not modelled by the validator: {note}", "warning"))


def _check_zone_gateways(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    fw = net.routers[_firewall(topo)]
    for zone in topo.zones.values():
        if not zone.interface or zone.name == "outside":
            continue
        ri = fw.interfaces.get(zone.interface)
        if ri is None:
            issues.append(Issue("D-02", fw.name, f"zone {zone.name}: interface {zone.interface} is not configured"))
            continue
        if ri.ip is None or ri.ip.ip != zone.gateway or ri.ip.network != zone.subnet:
            got = str(ri.ip) if ri.ip else "no address"
            issues.append(Issue("D-02", fw.name, f"{ri.name} has {got}, zone {zone.name} needs {zone.gateway}/{zone.subnet.prefixlen}"))
        if ri.shutdown:
            issues.append(Issue("D-02", fw.name, f"{ri.name} (zone {zone.name}) is shut down"))
        if zone.vlan is not None and "." in zone.interface and ri.dot1q != zone.vlan:
            issues.append(Issue("D-02", fw.name, f"{ri.name} uses dot1Q {ri.dot1q}, zone {zone.name} is VLAN {zone.vlan}"))
        if ri.nat != "inside":
            issues.append(Issue("D-02", fw.name, f"{ri.name} (zone {zone.name}) is not 'ip nat inside'"))


def _check_outside(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    fw, isp = net.routers[_firewall(topo)], net.routers[_upstream(topo)]
    outside, internet = topo.zones["outside"], topo.zones["internet"]
    ri = fw.interfaces.get(outside.interface or "")
    if ri is None or ri.ip is None:
        issues.append(Issue("D-03", fw.name, f"outside interface {outside.interface} has no address"))
    else:
        if ri.ip.ip != topo.pat_address or ri.ip.network != outside.subnet:
            issues.append(Issue("D-03", fw.name, f"{ri.name} has {ri.ip}, expected {topo.pat_address}/{outside.subnet.prefixlen}"))
        if ri.nat != "outside":
            issues.append(Issue("D-03", fw.name, f"{ri.name} is not 'ip nat outside'"))
    for zone, label in ((outside, "transit"), (internet, "Internet LAN")):
        hit = isp.interface_with_ip(zone.gateway)
        if hit is None or hit.ip.network != zone.subnet:
            issues.append(Issue("D-03", isp.name, f"no interface carries the {label} gateway {zone.gateway}/{zone.subnet.prefixlen}"))
        elif hit.shutdown:
            issues.append(Issue("D-03", isp.name, f"{hit.name} ({label}) is shut down"))


def _check_hosts(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    for host in topo.hosts.values():
        zone = topo.zones[host.zone]
        sw = net.switches.get(host.attach.node)
        port = sw.ports.get(host.attach.port or "") if sw else None
        if port is None:
            issues.append(Issue("D-04", host.attach.node, f"{host.name}: port {host.attach.port} does not exist in the configuration"))
            continue
        if port.shutdown:
            issues.append(Issue("D-04", sw.name, f"{port.name} ({host.name}) is shut down"))
        if port.mode != "access":
            issues.append(Issue("D-04", sw.name, f"{port.name} ({host.name}) is mode {port.mode or 'default'}, expected access"))
        if zone.vlan is not None and port.access_vlan != zone.vlan:
            issues.append(Issue("D-04", sw.name, f"{port.name} ({host.name}) is in VLAN {port.access_vlan}, zone {zone.name} is VLAN {zone.vlan}"))
        if zone.vlan is not None and zone.vlan not in sw.vlans:
            issues.append(Issue("D-06", sw.name, f"VLAN {zone.vlan} ({zone.name}) is used by {host.name} but not declared with 'vlan {zone.vlan}'"))
        link = topo.link_of(host.name)
        if link is not None and link.vlan is not None and zone.vlan is not None and link.vlan != zone.vlan:
            issues.append(Issue("D-04", "topology", f"link of {host.name} says VLAN {link.vlan}, zone {zone.name} is VLAN {zone.vlan}"))


def _interface_exists(net: Network, node: str, port: str) -> tuple[bool, bool]:
    """``(exists, up)`` for a device port named in a link."""
    dev = net.device(node)
    if isinstance(dev, RouterModel):
        ri = dev.interfaces.get(port)
        return ri is not None, bool(ri and ri.up)
    sp = dev.ports.get(port)
    return sp is not None, bool(sp and sp.up)


def _check_links(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    for link in topo.links:
        for end in (link.a, link.b):
            if end.node not in topo.devices:
                continue
            exists, up = _interface_exists(net, end.node, end.port or "")
            if not exists:
                issues.append(Issue("D-05", end.node, f"{end.port} (link {link.a} - {link.b}) is not present in the configuration"))
            elif not up:
                issues.append(Issue("D-05", end.node, f"{end.port} (link {link.a} - {link.b}) is shut down"))
        ends = [(e, net.device(e.node)) for e in (link.a, link.b) if e.node in topo.devices]
        switch_ends = [(e, d) for e, d in ends if isinstance(d, SwitchModel)]
        router_ends = [(e, d) for e, d in ends if isinstance(d, RouterModel)]
        for e, sw in switch_ends:
            port = sw.ports.get(e.port or "")
            if port is None:
                continue
            if link.kind == "trunk" and port.mode != "trunk":
                issues.append(Issue("D-05", sw.name, f"{port.name} should be a trunk (link {link.a} - {link.b}), mode is {port.mode or 'default'}"))
            if link.kind == "access" and port.mode != "access":
                issues.append(Issue("D-05", sw.name, f"{port.name} should be an access port, mode is {port.mode or 'default'}"))
            if link.kind == "access" and link.vlan is not None and port.access_vlan != link.vlan:
                issues.append(Issue("D-05", sw.name, f"{port.name} is in VLAN {port.access_vlan}, the link is VLAN {link.vlan}"))
        for e, rt in router_ends:
            if link.kind == "trunk":
                parent = rt.interfaces.get(e.port or "")
                if parent is not None and parent.ip is not None:
                    issues.append(Issue("D-05", rt.name, f"{e.port} is a trunk parent and should carry no address"))
                for vlan in link.vlans:
                    zone = _zone_by_vlan(topo, vlan)
                    sub = next((i for i in rt.interfaces.values() if i.name.startswith(f"{e.port}.") and i.dot1q == vlan), None)
                    if sub is None:
                        issues.append(Issue("D-05", rt.name, f"no subinterface of {e.port} carries VLAN {vlan}"))
                    elif zone and (sub.ip is None or sub.ip.ip != zone.gateway):
                        issues.append(Issue("D-05", rt.name, f"{sub.name} should hold {zone.gateway} (zone {zone.name})"))
            elif link.kind == "access" and link.vlan is not None:
                zone = _zone_by_vlan(topo, link.vlan)
                ri = rt.interfaces.get(e.port or "")
                if zone and ri is not None and (ri.ip is None or ri.ip.network != zone.subnet):
                    issues.append(Issue("D-05", rt.name, f"{ri.name} is not in {zone.subnet} (zone {zone.name}, VLAN {link.vlan})"))
        if link.kind == "routed":
            addrs = []
            for e, rt in router_ends:
                ri = rt.interfaces.get(e.port or "")
                addrs.append((rt.name, ri.ip if ri else None))
            if len(addrs) == 2 and all(ip is not None for _n, ip in addrs) and addrs[0][1].network != addrs[1][1].network:
                issues.append(Issue("D-05", "topology", f"routed link {link.a} - {link.b}: the two ends are in different subnets ({addrs[0][1]} / {addrs[1][1]})"))


def _check_vlans_and_trunks(net: Network, issues: list[Issue], hardened: bool) -> None:
    topo = net.topology
    for link in topo.links:
        if link.kind != "trunk":
            continue
        for end in (link.a, link.b):
            sw = net.switches.get(end.node)
            if sw is None:
                continue
            for vlan in link.vlans:
                if vlan not in sw.vlans:
                    issues.append(Issue("D-06", sw.name, f"VLAN {vlan} crosses trunk {end.port} but is not declared with 'vlan {vlan}'"))
            port = sw.ports.get(end.port or "")
            if port is None or not hardened:
                continue
            if port.trunk_vlans is None:
                issues.append(Issue("D-06", sw.name, f"{port.name} allows every VLAN; hardened design allows exactly {sorted(link.vlans)}"))
            elif set(port.trunk_vlans) != set(link.vlans):
                issues.append(Issue("D-06", sw.name, f"{port.name} allows VLANs {sorted(port.trunk_vlans)}, the link carries {sorted(link.vlans)}"))
            if port.native_vlan == 1 or (port.trunk_vlans is not None and port.native_vlan in port.trunk_vlans):
                issues.append(Issue("D-06", sw.name, f"{port.name} native VLAN {port.native_vlan} must be an unused VLAN that the trunk does not carry"))


def _check_management(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    for dev, ip in topo.management.items():
        zone = topo.zone_of(ip)
        model = net.device(dev)
        if zone is None:
            issues.append(Issue("D-07", dev, f"management address {ip} is in no zone"))
            continue
        if isinstance(model, RouterModel):
            ri = model.interface_with_ip(ip)
            if ri is None or ri.shutdown:
                issues.append(Issue("D-07", dev, f"no active interface holds management address {ip}"))
            continue
        mgmt = model.management_ip()
        if mgmt != ip:
            issues.append(Issue("D-07", dev, f"active SVI address is {mgmt}, expected {ip}"))
            continue
        vlan = next((v for v, a in model.svis.items() if a.ip == ip), None)
        if zone.vlan is not None and vlan != zone.vlan:
            issues.append(Issue("D-07", dev, f"{ip} sits on interface Vlan{vlan}, zone {zone.name} is VLAN {zone.vlan}"))
        if model.svis[vlan].network != zone.subnet:
            issues.append(Issue("D-07", dev, f"SVI mask puts {ip} in {model.svis[vlan].network}, expected {zone.subnet}"))
        if model.default_gateway != zone.gateway:
            issues.append(Issue("D-07", dev, f"default gateway is {model.default_gateway}, expected {zone.gateway}"))
        if 1 in model.svi_up and model.svi_up[1] and 1 in model.svis:
            issues.append(Issue("D-07", dev, "interface Vlan1 carries an address and is up"))


def _check_nat(net: Network, issues: list[Issue], hardened: bool) -> None:
    topo = net.topology
    fw = net.routers[_firewall(topo)]
    want = {(s.inside, s.outside) for s in topo.static_nat}
    have = {(e.inside, e.outside) for e in fw.nat_static}
    for inside, outside in sorted(want - have):
        issues.append(Issue("D-08", fw.name, f"missing static NAT {inside} -> {outside}"))
    for inside, outside in sorted(have - want):
        issues.append(Issue("D-08", fw.name, f"static NAT {inside} -> {outside} is not in the topology"))
    if len(fw.nat_pat) != 1:
        issues.append(Issue("D-08", fw.name, f"expected one PAT rule, found {len(fw.nat_pat)}"))
        return
    pat = fw.nat_pat[0]
    if pat.interface != topo.pat_interface.port:
        issues.append(Issue("D-08", fw.name, f"PAT uses {pat.interface}, topology says {topo.pat_interface.port}"))
    acl = fw.acls.get(pat.acl)
    if acl is None:
        issues.append(Issue("D-08", fw.name, f"PAT references ACL {pat.acl}, which is not defined"))
    elif hardened:
        for zone in topo.zones.values():
            if zone.interface is None or zone.name in ("outside", "internet"):
                continue
            probe = Packet.make("ip", str(zone.subnet[50]), "198.51.100.80")
            permitted = acl.evaluate(probe).action == "permit"
            if permitted != (zone.name in topo.pat_sources):
                issues.append(Issue("D-08", fw.name, f"PAT ACL {pat.acl} {'permits' if permitted else 'does not permit'} zone {zone.name}; "
                                    f"topology says it {'should' if zone.name in topo.pat_sources else 'should not'} be translated"))


def _check_routing(net: Network, issues: list[Issue], hardened: bool) -> None:
    topo = net.topology
    fw, isp = net.routers[_firewall(topo)], net.routers[_upstream(topo)]
    outside = topo.zones["outside"]
    default = [r for r in fw.routes if r.network.prefixlen == 0]
    if len(default) != 1 or default[0].next_hop != outside.gateway:
        issues.append(Issue("D-09", fw.name, f"expected one default route via {outside.gateway}, found {[str(r.next_hop) for r in default]}"))
    block = topo.public_block
    back = [r for r in isp.routes if r.network == block]
    if len(back) != 1 or back[0].next_hop != topo.pat_address:
        issues.append(Issue("D-09", isp.name, f"expected a route to {block} via {topo.pat_address}"))
    if hardened and not any(r.network == block and r.discard for r in fw.routes):
        issues.append(Issue("D-09", fw.name, f"no discard (Null0) route for the public NAT block {block}"))
    for router in (fw, isp):
        for r in router.routes:
            if r.next_hop is not None and router.connected_interface(r.next_hop) is None:
                issues.append(Issue("D-09", router.name, f"next hop {r.next_hop} of route to {r.network} is not on a connected subnet"))
        if any("ospf" in l.words or "rip" in l.words for l in router.cfg.top("router")):
            issues.append(Issue("D-09", router.name, "a routing protocol is configured; the design uses static routes only"))


def _check_dhcp(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    fw = net.routers[_firewall(topo)]
    pools = {p: line for p, line in _dhcp_pools(fw.cfg)}
    excluded = _excluded(fw.cfg)
    for zone in topo.zones.values():
        hosts = [h for h in topo.hosts.values() if h.zone == zone.name]
        if zone.addressing == "dhcp":
            if zone.subnet not in pools:
                issues.append(Issue("D-14", fw.name, f"zone {zone.name} is DHCP-addressed but there is no pool for {zone.subnet}"))
                continue
            first = next((a for a in zone.subnet.hosts()
                          if a != zone.gateway and not any(lo <= a <= hi for lo, hi in excluded)), None)
            if len(hosts) == 1 and hosts[0].ip != first:
                issues.append(Issue("D-14", fw.name, f"the first lease of pool {zone.subnet} is {first}, the topology expects {hosts[0].name} at {hosts[0].ip}"))
        elif zone.subnet in pools:
            issues.append(Issue("D-14", fw.name, f"zone {zone.name} is statically addressed but a DHCP pool serves {zone.subnet}", "warning"))


def _check_unique_addresses(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    owners: dict[IPv4, list[str]] = {}

    def add(ip: IPv4, who: str) -> None:
        owners.setdefault(ip, []).append(who)

    for r in net.routers.values():
        for i in r.interfaces.values():
            if i.ip is not None and i.up:
                add(i.ip.ip, f"{r.name} {i.name}")
    for s in net.switches.values():
        for vlan, addr in s.svis.items():
            if s.svi_up.get(vlan):
                add(addr.ip, f"{s.name} Vlan{vlan}")
    for h in topo.hosts.values():
        add(h.ip, f"host {h.name}")
    for s in topo.static_nat:
        add(s.outside, f"static NAT of {s.host}")
    for ip, who in sorted(owners.items()):
        if len(who) > 1:
            issues.append(Issue("D-13", "network", f"{ip} is used by {', '.join(who)}"))


def _check_zone_filtering(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    fw = net.routers[_firewall(topo)]
    for zone in topo.zones.values():
        if not zone.interface:
            continue
        ri = fw.interfaces.get(zone.interface)
        if ri is None:
            continue
        if ri.acl_in is None:
            issues.append(Issue("D-10", fw.name, f"{ri.name} (zone {zone.name}) has no inbound ACL"))
            continue
        acl = fw.acls.get(ri.acl_in)
        if acl is None or not acl.entries:
            issues.append(Issue("D-10", fw.name, f"{ri.name}: inbound ACL {ri.acl_in} is undefined or empty (IOS then permits everything)"))
            continue
        last = acl.entries[-1]
        if not (last.action == "deny" and last.is_any_any):
            issues.append(Issue("D-10", fw.name, f"{ri.acl_in} does not end with 'deny ip any any'"))
        if ri.acl_out is not None:
            issues.append(Issue("D-10", fw.name, f"{ri.name} also filters outbound ({ri.acl_out}); the design filters inbound only", "warning"))


def _check_service_targets(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    syslog = topo.hosts[topo.services["syslog"]["host"]].ip
    ntp = topo.hosts[topo.services["ntp"]["host"]].ip
    for name, spec in topo.devices.items():
        if not spec.audited:
            continue
        cfg = net.device(name).cfg
        if str(syslog) not in _logging_hosts(cfg):
            issues.append(Issue("D-11", name, f"does not send syslog to {syslog}"))
        if str(ntp) not in _ntp_servers(cfg):
            issues.append(Issue("D-11", name, f"does not use {ntp} as NTP server"))


def _check_admin_only(net: Network, issues: list[Issue]) -> None:
    topo = net.topology
    admin = topo.admin_host().ip
    for name, spec in topo.devices.items():
        if not spec.audited:
            continue
        model = net.device(name)
        if not model.vty:
            issues.append(Issue("D-12", name, "no VTY lines are configured"))
        for vty in model.vty:
            if vty.transport != frozenset({"ssh"}):
                issues.append(Issue("D-12", name, f"{vty.label} accepts {sorted(vty.transport) if vty.transport else 'every transport'}, only ssh is allowed"))
            acl = model.acls.get(vty.access_class or "")
            if acl is None:
                issues.append(Issue("D-12", name, f"{vty.label} has no usable access-class"))
                continue
            probe_dst = str(topo.management.get(name, IPv4("192.0.2.1")))  # a standard ACL only looks at the source
            if acl.evaluate(Packet.make("tcp", str(admin), probe_dst, dport=22)).action != "permit":
                issues.append(Issue("D-12", name, f"{vty.label}: access-class {vty.access_class} blocks the administrator host {admin}"))
            for host in topo.hosts.values():
                if host.ip != admin and acl.evaluate(Packet.make("tcp", str(host.ip), probe_dst, dport=22)).action == "permit":
                    issues.append(Issue("D-12", name, f"{vty.label}: access-class {vty.access_class} admits {host.name} ({host.ip})"))


# --------------------------------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------------------------------

CHECKS = {
    "D-01": "device identity matches the topology",
    "D-02": "firewall zone gateways: address, mask, dot1Q, NAT inside",
    "D-03": "outside link and Internet LAN addressing",
    "D-04": "every host is on an access port in its zone's VLAN",
    "D-05": "every cable has configured, enabled and consistent ends",
    "D-06": "VLAN database and trunk pruning (pruning: hardened only)",
    "D-07": "management addresses, SVIs and default gateways",
    "D-08": "NAT matches the topology (PAT scope: hardened only)",
    "D-09": "static routing is consistent (Null0 discard route: hardened only)",
    "D-10": "every zone interface has a default-deny inbound ACL (hardened only)",
    "D-11": "syslog and NTP point at the log server (hardened only)",
    "D-12": "management is SSH-only from the administrator host (hardened only)",
    "D-13": "no address is used twice",
    "D-14": "DHCP pools match the topology",
}


def check_design(topology: Topology, state: str) -> list[Issue]:
    """Run every consistency check for one state ('baseline' or 'hardened')."""
    issues: list[Issue] = []
    try:
        net = load_network(topology, state)
    except TopologyError as exc:
        return [Issue("D-01", "topology", str(exc))]
    hardened = state == "hardened"
    _check_identity(net, issues)
    _check_zone_gateways(net, issues)
    _check_outside(net, issues)
    _check_hosts(net, issues)
    _check_links(net, issues)
    _check_vlans_and_trunks(net, issues, hardened)
    _check_management(net, issues)
    _check_nat(net, issues, hardened)
    _check_routing(net, issues, hardened)
    _check_dhcp(net, issues)
    _check_unique_addresses(net, issues)
    if hardened:
        _check_zone_filtering(net, issues)
        _check_service_targets(net, issues)
        _check_admin_only(net, issues)
    return issues
