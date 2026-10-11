"""Typed views of the five device configurations, used by the design checker and the policy validator.

Everything here is read from the configuration files; nothing is assumed from the topology.  Only the IOS features the
lab uses are modelled (connected and static routes, inbound/outbound interface ACLs, static NAT and PAT, VLAN
membership, SVIs, VTY restrictions).  Anything else is ignored rather than guessed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from ..acl import ACL
from ..parser import ConfigLine, DeviceConfig, Interface, canon_ifname, load_config
from .topology import Topology, TopologyError

IPv4 = ipaddress.IPv4Address
IPv4Net = ipaddress.IPv4Network


@dataclass
class RouterInterface:
    name: str
    iface: Interface
    ip: ipaddress.IPv4Interface | None
    shutdown: bool
    acl_in: str | None
    acl_out: str | None
    nat: str | None  # "inside" | "outside" | None
    dot1q: int | None  # VLAN id of a subinterface

    @property
    def up(self) -> bool:
        return not self.shutdown

    @property
    def network(self) -> IPv4Net | None:
        return self.ip.network if self.ip else None


@dataclass(frozen=True)
class StaticRoute:
    network: IPv4Net
    next_hop: IPv4 | None
    interface: str | None  # outgoing interface for routes without a next hop ("Null0" discards)
    line: ConfigLine

    @property
    def discard(self) -> bool:
        return (self.interface or "").lower().startswith("null")


@dataclass(frozen=True)
class NatStaticEntry:
    inside: IPv4
    outside: IPv4
    line: ConfigLine


@dataclass(frozen=True)
class NatPatEntry:
    acl: str
    interface: str
    line: ConfigLine


@dataclass
class RouterModel:
    name: str
    cfg: DeviceConfig
    interfaces: dict[str, RouterInterface] = field(default_factory=dict)
    routes: list[StaticRoute] = field(default_factory=list)
    nat_static: list[NatStaticEntry] = field(default_factory=list)
    nat_pat: list[NatPatEntry] = field(default_factory=list)
    vty: list["VtyPolicy"] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # configuration the model could not interpret

    @property
    def acls(self) -> dict[str, ACL]:
        return self.cfg.acls

    def interface_with_ip(self, ip: IPv4) -> RouterInterface | None:
        return next((i for i in self.interfaces.values() if i.ip and i.ip.ip == ip), None)

    def connected_interface(self, ip: IPv4) -> RouterInterface | None:
        """The up interface whose subnet contains ``ip`` (longest prefix wins)."""
        hits = [i for i in self.interfaces.values() if i.up and i.ip and ip in i.ip.network]
        return max(hits, key=lambda i: i.ip.network.prefixlen) if hits else None

    def route(self, dst: IPv4) -> tuple[str, RouterInterface | StaticRoute | None]:
        """Longest-prefix match: ``("connected", iface)``, ``("static", route)`` or ``("none", None)``."""
        best: tuple[int, str, object] | None = None
        conn = self.connected_interface(dst)
        if conn is not None:
            best = (conn.ip.network.prefixlen, "connected", conn)
        for r in self.routes:
            if dst in r.network and (best is None or r.network.prefixlen > best[0]):
                best = (r.network.prefixlen, "static", r)
        if best is None:
            return "none", None
        return best[1], best[2]  # type: ignore[return-value]


@dataclass
class SwitchPort:
    name: str
    iface: Interface
    shutdown: bool
    mode: str | None  # access | trunk | dynamic-... | None
    access_vlan: int
    trunk_vlans: frozenset[int] | None  # None = all VLANs
    native_vlan: int
    port_security: bool

    @property
    def up(self) -> bool:
        return not self.shutdown


@dataclass
class VtyPolicy:
    label: str
    access_class: str | None
    transport: frozenset[str] | None  # None = IOS default (all transports)


@dataclass
class SwitchModel:
    name: str
    cfg: DeviceConfig
    vlans: dict[int, str] = field(default_factory=dict)
    ports: dict[str, SwitchPort] = field(default_factory=dict)
    svis: dict[int, ipaddress.IPv4Interface] = field(default_factory=dict)
    svi_up: dict[int, bool] = field(default_factory=dict)
    default_gateway: IPv4 | None = None
    vty: list[VtyPolicy] = field(default_factory=list)

    @property
    def acls(self) -> dict[str, ACL]:
        return self.cfg.acls

    def management_ip(self) -> IPv4 | None:
        ups = [(v, a) for v, a in self.svis.items() if self.svi_up.get(v) and a]
        return ups[0][1].ip if len(ups) == 1 else None


@dataclass
class Network:
    topology: Topology
    state: str
    routers: dict[str, RouterModel] = field(default_factory=dict)
    switches: dict[str, SwitchModel] = field(default_factory=dict)

    @property
    def configs(self) -> dict[str, DeviceConfig]:
        return {**{n: r.cfg for n, r in self.routers.items()}, **{n: s.cfg for n, s in self.switches.items()}}

    def device(self, name: str) -> RouterModel | SwitchModel:
        return self.routers.get(name) or self.switches[name]


# --------------------------------------------------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------------------------------------------------


def _vlan_set(text: str) -> frozenset[int] | None:
    text = text.strip().lower()
    if text in ("all", ""):
        return None
    ids: set[int] = set()
    mode = "set"
    for part in text.replace(" ", ",").split(","):
        if part in ("add", "remove", "except", "none"):
            mode = part
            continue
        lo, dash, hi = part.partition("-")
        if lo.isdigit() and (not dash or hi.isdigit()):
            rng = range(int(lo), int(hi or lo) + 1)
            if mode == "remove" or mode == "except":
                ids -= set(rng)
            else:
                ids |= set(rng)
    return frozenset(ids)


def _exact(iface: Interface, *words: str) -> bool:
    """True if the last statement that is exactly ``words`` (or its 'no' form) enables it."""
    state = False
    for c in iface.commands:
        if c.words == words:
            state = True
        elif c.words == ("no",) + words:
            state = False
    return state


def _router_interface(iface: Interface) -> RouterInterface:
    groups = iface.access_groups
    nat = "inside" if iface.has("ip", "nat", "inside") else "outside" if iface.has("ip", "nat", "outside") else None
    dot1q = None
    enc = iface.get("encapsulation", "dot1q")
    if enc is not None and len(enc.words) >= 3 and enc.words[2].isdigit():
        dot1q = int(enc.words[2])
    return RouterInterface(
        name=iface.name, iface=iface, ip=iface.ip, shutdown=iface.shutdown,
        acl_in=groups["in"][0] if "in" in groups else None,
        acl_out=groups["out"][0] if "out" in groups else None, nat=nat, dot1q=dot1q,
    )


def build_router(cfg: DeviceConfig, name: str) -> RouterModel:
    model = RouterModel(name=name, cfg=cfg)
    for iface in cfg.interfaces:
        if iface.kind in ("physical", "subinterface", "loopback", "svi"):
            model.interfaces[iface.name] = _router_interface(iface)

    for line in cfg.top("ip", "route"):
        tokens = line.text.split()
        if len(tokens) < 5:
            model.notes.append(f"line {line.no}: unrecognised static route '{line.text}'")
            continue
        try:
            net = ipaddress.IPv4Network(f"{tokens[2]}/{tokens[3]}")
        except ValueError:
            model.notes.append(f"line {line.no}: unrecognised static route '{line.text}'")
            continue
        try:
            model.routes.append(StaticRoute(net, IPv4(tokens[4]), None, line))
        except ValueError:
            model.routes.append(StaticRoute(net, None, canon_ifname(tokens[4]), line))

    for line in cfg.top("ip", "nat", "inside", "source"):
        t = line.text.split()
        if len(t) >= 7 and t[4].lower() == "static" and _is_ip(t[5]) and _is_ip(t[6]) and len(t) == 7:
            model.nat_static.append(NatStaticEntry(IPv4(t[5]), IPv4(t[6]), line))
        elif len(t) >= 8 and t[4].lower() == "list" and t[6].lower() == "interface":
            if "overload" in (x.lower() for x in t[8:]):
                model.nat_pat.append(NatPatEntry(t[5], canon_ifname(t[7]), line))
            else:
                model.notes.append(f"line {line.no}: NAT without 'overload' is not modelled")
        else:
            model.notes.append(f"line {line.no}: NAT form not modelled: '{line.text}'")
    model.vty = vty_of(cfg)
    return model


def _is_ip(text: str) -> bool:
    try:
        IPv4(text)
        return True
    except ValueError:
        return False


def build_switch(cfg: DeviceConfig, name: str) -> SwitchModel:
    model = SwitchModel(name=name, cfg=cfg)
    for line in cfg.top("vlan"):
        words = line.words
        if len(words) == 2 and words[1].isdigit():
            nm = line.child_starting("name")
            model.vlans[int(words[1])] = nm.rest("name") if nm else f"VLAN{int(words[1]):04d}"

    gw = cfg.top_one("ip", "default-gateway")
    if gw and len(gw.words) >= 3 and _is_ip(gw.words[2]):
        model.default_gateway = IPv4(gw.words[2])

    for iface in cfg.interfaces:
        if iface.kind == "svi":
            vid = int(iface.name.lower().removeprefix("vlan")) if iface.name.lower().removeprefix("vlan").isdigit() else None
            if vid is not None:
                if iface.ip:
                    model.svis[vid] = iface.ip
                model.svi_up[vid] = not iface.shutdown
        elif iface.kind == "physical":
            mode = iface.explicit_mode
            access = iface.get("switchport", "access", "vlan")
            trunk = iface.get("switchport", "trunk", "allowed", "vlan")
            native = iface.get("switchport", "trunk", "native", "vlan")
            model.ports[iface.name] = SwitchPort(
                name=iface.name, iface=iface, shutdown=iface.shutdown, mode=mode,
                access_vlan=int(access.words[3]) if access and len(access.words) > 3 and access.words[3].isdigit() else 1,
                trunk_vlans=_vlan_set(trunk.rest("switchport", "trunk", "allowed", "vlan")) if trunk else None,
                native_vlan=int(native.words[4]) if native and len(native.words) > 4 and native.words[4].isdigit() else 1,
                port_security=_exact(iface, "switchport", "port-security"),
            )

    model.vty = vty_of(cfg)
    return model


def vty_of(cfg: DeviceConfig) -> list[VtyPolicy]:
    out = []
    for blk in cfg.lines_of("vty"):
        ac = blk.access_class_in
        ti = blk.transport_input
        out.append(VtyPolicy(blk.label, ac[0] if ac else None, ti[0] if ti else None))
    return out


def load_network(topology: Topology, state: str) -> Network:
    """Parse every device configuration of ``state`` and build the typed models."""
    net = Network(topology=topology, state=state)
    for name, spec in topology.devices.items():
        path: Path = topology.config_path(state, name)
        try:
            cfg = load_config(path)
        except Exception as exc:  # noqa: BLE001 - report the file, keep the message
            raise TopologyError(f"{name}: cannot load {path}: {exc}") from exc
        cfg.name = name
        if spec.kind == "router":
            net.routers[name] = build_router(cfg, name)
        else:
            net.switches[name] = build_switch(cfg, name)
    return net
