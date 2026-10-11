"""Load and validate ``topology/topology.yaml``, the description of the lab design.

The topology says *what the network is meant to be* (zones, hosts, cabling, NAT, management addresses).
The device configurations say *what the devices actually do*.  :mod:`ciscoaudit.policy.design` compares the two,
and :mod:`ciscoaudit.policy.network` builds the packet-level model from both.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..parser import canon_ifname

STATES = ("baseline", "hardened")
SIM_DIR = "internet-sim"  # configurations of the simulated Internet, shared by both states
_LINK_KINDS = {"trunk", "access", "routed"}
_ORIGINS = {"reused", "re-patched", "moved", "new"}


class TopologyError(Exception):
    """The topology file is malformed or contradicts itself."""


@dataclass(frozen=True)
class Endpoint:
    node: str
    port: str | None = None  # canonical interface name; None for an end device's single NIC

    @classmethod
    def parse(cls, text: str) -> "Endpoint":
        node, sep, port = str(text).partition(":")
        return cls(node.strip(), canon_ifname(port) if sep else None)

    def __str__(self) -> str:
        return f"{self.node}:{self.port}" if self.port else self.node


@dataclass(frozen=True)
class DeviceSpec:
    name: str
    pt_label: str
    kind: str  # router | switch
    model: str
    ios: str
    role: str
    audited: bool


@dataclass(frozen=True)
class Zone:
    name: str
    description: str
    vlan: int | None
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    interface: str | None  # canonical name of the FW-EDGE (sub)interface that holds the gateway address
    addressing: str  # static | dhcp


@dataclass(frozen=True)
class HostSpec:
    name: str
    model: str
    zone: str
    ip: ipaddress.IPv4Address
    attach: Endpoint
    role: str
    origin: str


@dataclass(frozen=True)
class LinkSpec:
    a: Endpoint
    b: Endpoint
    kind: str
    vlan: int | None
    vlans: tuple[int, ...]
    origin: str
    note: str = ""


@dataclass(frozen=True)
class StaticNat:
    host: str
    inside: ipaddress.IPv4Address
    outside: ipaddress.IPv4Address


@dataclass
class Topology:
    path: Path
    name: str
    devices: dict[str, DeviceSpec]
    retired: list[dict[str, str]]
    zones: dict[str, Zone]
    hosts: dict[str, HostSpec]
    links: list[LinkSpec]
    pat_interface: Endpoint
    pat_address: ipaddress.IPv4Address
    pat_sources: tuple[str, ...]
    public_block: ipaddress.IPv4Network
    static_nat: list[StaticNat]
    services: dict[str, Any]
    management: dict[str, ipaddress.IPv4Address]
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    # -- lookups ----------------------------------------------------------------------------------------------------
    @property
    def root(self) -> Path:
        return self.path.resolve().parent.parent

    def zone_of(self, ip: ipaddress.IPv4Address | str) -> Zone | None:
        addr = ipaddress.IPv4Address(ip)
        matches = [z for z in self.zones.values() if addr in z.subnet]
        return max(matches, key=lambda z: z.subnet.prefixlen) if matches else None

    def host_by_ip(self, ip: ipaddress.IPv4Address | str) -> HostSpec | None:
        addr = ipaddress.IPv4Address(ip)
        return next((h for h in self.hosts.values() if h.ip == addr), None)

    def node_ips(self) -> dict[str, ipaddress.IPv4Address]:
        """Every named endpoint that can be a flow source or destination: hosts and managed devices."""
        ips = {name: h.ip for name, h in self.hosts.items()}
        ips.update(self.management)
        return ips

    def config_path(self, state: str, device: str) -> Path:
        if state not in STATES:
            raise TopologyError(f"unknown state {state!r}; expected one of {', '.join(STATES)}")
        spec = self.devices[device]
        folder = state if spec.audited else SIM_DIR
        return self.root / "configs" / folder / f"{device}.cfg"

    def config_paths(self, state: str) -> dict[str, Path]:
        return {name: self.config_path(state, name) for name in self.devices}

    def admin_host(self) -> HostSpec:
        return self.hosts[self.services["admin_host"]]

    def link_of(self, node: str, port: str | None = None) -> LinkSpec | None:
        want = canon_ifname(port) if port else None
        for link in self.links:
            for end in (link.a, link.b):
                if end.node == node and (want is None or end.port == want):
                    return link
        return None


# --------------------------------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------------------------------


def _req(mapping: dict, key: str, where: str) -> Any:
    if not isinstance(mapping, dict) or key not in mapping or mapping[key] is None and key not in ("interface",):
        raise TopologyError(f"{where}: missing '{key}'")
    return mapping[key]


def _ip(value: Any, where: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(str(value))
    except ValueError as exc:
        raise TopologyError(f"{where}: {value!r} is not an IPv4 address") from exc


def _net(value: Any, where: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(str(value), strict=True)
    except ValueError as exc:
        raise TopologyError(f"{where}: {value!r} is not an IPv4 network") from exc


def load_topology(path: str | Path) -> Topology:
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TopologyError(f"{path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        raise TopologyError(f"{path}: not a topology file (expected 'schema: 1')")

    devices: dict[str, DeviceSpec] = {}
    for name, d in (raw.get("devices") or {}).items():
        where = f"devices.{name}"
        kind = str(_req(d, "kind", where))
        if kind not in ("router", "switch"):
            raise TopologyError(f"{where}: kind must be router or switch")
        devices[name] = DeviceSpec(name, str(_req(d, "pt_label", where)), kind, str(_req(d, "model", where)),
                                   str(_req(d, "ios", where)), str(_req(d, "role", where)), bool(d.get("audited", True)))
    if not devices:
        raise TopologyError(f"{path}: no devices")

    zones: dict[str, Zone] = {}
    for name, z in (raw.get("zones") or {}).items():
        where = f"zones.{name}"
        subnet = _net(_req(z, "subnet", where), where)
        gateway = _ip(_req(z, "gateway", where), where)
        if gateway not in subnet:
            raise TopologyError(f"{where}: gateway {gateway} is not inside {subnet}")
        iface = z.get("interface")
        vlan = z.get("vlan")
        zones[name] = Zone(name, str(z.get("description", "")), int(vlan) if vlan is not None else None, subnet, gateway,
                           canon_ifname(str(iface)) if iface else None, str(z.get("addressing", "static")))
    overlaps = [(a.name, b.name) for i, a in enumerate(zones.values()) for b in list(zones.values())[i + 1:]
                if a.subnet.overlaps(b.subnet)]
    if overlaps:
        raise TopologyError(f"zones overlap: {overlaps}")

    hosts: dict[str, HostSpec] = {}
    for name, h in (raw.get("hosts") or {}).items():
        where = f"hosts.{name}"
        zone = str(_req(h, "zone", where))
        if zone not in zones:
            raise TopologyError(f"{where}: unknown zone {zone!r}")
        ip = _ip(_req(h, "ip", where), where)
        if ip not in zones[zone].subnet:
            raise TopologyError(f"{where}: {ip} is outside zone {zone} ({zones[zone].subnet})")
        attach = Endpoint.parse(_req(h, "attach", where))
        if attach.node not in devices or devices[attach.node].kind != "switch" or not attach.port:
            raise TopologyError(f"{where}: attach must be '<switch>:<port>' of a known switch, got {h['attach']!r}")
        origin = str(_req(h, "origin", where))
        if origin not in _ORIGINS:
            raise TopologyError(f"{where}: origin must be one of {sorted(_ORIGINS)}")
        hosts[name] = HostSpec(name, str(_req(h, "model", where)), zone, ip, attach, str(_req(h, "role", where)), origin)
    dupes = {ip for ip in (h.ip for h in hosts.values()) if [x.ip for x in hosts.values()].count(ip) > 1}
    if dupes:
        raise TopologyError(f"duplicate host addresses: {sorted(str(d) for d in dupes)}")
    if set(hosts) & set(devices):
        raise TopologyError(f"names used for both a host and a device: {sorted(set(hosts) & set(devices))}")

    links: list[LinkSpec] = []
    for i, l in enumerate(raw.get("links") or [], 1):
        where = f"links[{i}]"
        a, b = Endpoint.parse(_req(l, "a", where)), Endpoint.parse(_req(l, "b", where))
        for end in (a, b):
            if end.node not in devices and end.node not in hosts:
                raise TopologyError(f"{where}: unknown node {end.node!r}")
            if end.node in devices and not end.port:
                raise TopologyError(f"{where}: {end.node} needs a port")
        kind = str(_req(l, "kind", where))
        if kind not in _LINK_KINDS:
            raise TopologyError(f"{where}: kind must be one of {sorted(_LINK_KINDS)}")
        origin = str(_req(l, "origin", where))
        if origin not in {"reused", "re-patched", "new"}:
            raise TopologyError(f"{where}: origin must be reused, re-patched or new")
        links.append(LinkSpec(a, b, kind, int(l["vlan"]) if l.get("vlan") is not None else None,
                              tuple(int(v) for v in l.get("vlans", ())), origin, str(l.get("note", ""))))
    ports = [str(e) for l in links for e in (l.a, l.b) if e.port]
    reused = sorted({p for p in ports if ports.count(p) > 1})
    if reused:
        raise TopologyError(f"ports cabled twice: {reused}")
    for h in hosts.values():
        if not any(h.name in (l.a.node, l.b.node) for l in links):
            raise TopologyError(f"host {h.name} has no link")
        link = next(l for l in links if h.name in (l.a.node, l.b.node))
        other = link.b if link.a.node == h.name else link.a
        if other != h.attach:
            raise TopologyError(f"host {h.name}: 'attach' says {h.attach} but the link goes to {other}")

    nat = raw.get("nat") or {}
    pat = nat.get("pat") or {}
    static_nat = []
    for n in nat.get("static") or []:
        static_nat.append(StaticNat(str(_req(n, "host", "nat.static")), _ip(_req(n, "inside", "nat.static"), "nat.static"),
                                    _ip(_req(n, "outside", "nat.static"), "nat.static")))
    public_block = _net(_req(nat, "public_block", "nat"), "nat.public_block")
    for s in static_nat:
        if s.outside not in public_block:
            raise TopologyError(f"nat.static {s.host}: {s.outside} is outside the public block {public_block}")
        if s.host not in hosts or hosts[s.host].ip != s.inside:
            raise TopologyError(f"nat.static {s.host}: inside address does not match the host's address")
    sources = tuple(str(x) for x in pat.get("sources", ()))
    for z in sources:
        if z not in zones:
            raise TopologyError(f"nat.pat.sources: unknown zone {z!r}")

    management = {str(k): _ip(v, f"management.{k}") for k, v in (raw.get("management") or {}).items()}
    for dev in management:
        if dev not in devices:
            raise TopologyError(f"management: unknown device {dev!r}")

    services = dict(raw.get("services") or {})
    if services.get("admin_host") not in hosts:
        raise TopologyError("services.admin_host must name a host")

    return Topology(
        path=p, name=str(raw.get("name", "")), devices=devices, retired=list(raw.get("retired") or []), zones=zones,
        hosts=hosts, links=links, pat_interface=Endpoint.parse(_req(pat, "interface", "nat.pat")),
        pat_address=_ip(_req(pat, "address", "nat.pat"), "nat.pat.address"), pat_sources=sources,
        public_block=public_block, static_nat=static_nat, services=services, management=management, raw=raw,
    )
