"""A flow is one packet exchange to be judged by the policy simulator.

Flows are written as one short line in the scenario files::

    PC0 -> SRV-APP tcp/443                       a client opening HTTPS to a server
    PC5 -> 203.0.113.9 tcp/80 spoof=10.10.10.10  the Internet attacker forging an internal source address
    SRV-APP -> PC0 tcp/3389 sport=80 ack         a crafted packet that only carries the ACK flag
    SW-DMZ -> SRV-LOG udp/514 oneway             syslog: no reply to wait for
    PC2 -> 255.255.255.255 udp/67 sport=68 spoof=0.0.0.0     a DHCP DISCOVER from a host without an address

``src`` and ``dst`` are host or device names from the topology, or IPv4 addresses (public NAT addresses, unused
addresses).  ``spoof=`` changes the source address written into the packet; the packet still enters the network where the
named sender is cabled.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

EPHEMERAL_PORT = 49152
PROTOCOLS = ("tcp", "udp", "icmp")
ICMP_TYPES = {"echo": 8, "echo-reply": 0, "unreachable": 3, "time-exceeded": 11}
_FLAGS = {"ack", "oneway"}
_KEYS = {"sport", "spoof"}
_LINE = re.compile(r"^(?P<src>\S+)\s*->\s*(?P<dst>\S+)\s+(?P<proto>\S+)(?P<rest>(?:\s+\S+)*)$")


class FlowError(ValueError):
    """A flow description that cannot be understood."""


@dataclass(frozen=True)
class FlowSpec:
    src: str
    dst: str
    proto: str  # tcp | udp | icmp
    dport: int | None = None
    sport: int | None = None
    icmp_type: str | None = None  # name from ICMP_TYPES
    ack: bool = False  # tcp: send ACK instead of SYN (a crafted packet, not part of a handshake)
    spoof: str | None = None  # source address placed in the packet
    oneway: bool = False  # no reply is expected (syslog, crafted packets, ICMP errors)

    @property
    def expects_reply(self) -> bool:
        if self.oneway or self.ack or self.spoof is not None:
            return False
        if self.proto == "icmp":
            return self.icmp_type == "echo"
        return True

    @property
    def source_port(self) -> int | None:
        if self.proto == "icmp":
            return None
        return self.sport if self.sport is not None else EPHEMERAL_PORT

    def __str__(self) -> str:
        if self.proto == "icmp":
            svc = f"icmp/{self.icmp_type}"
        else:
            svc = f"{self.proto}/{self.dport}"
        extras = []
        if self.sport is not None:
            extras.append(f"sport={self.sport}")
        if self.spoof:
            extras.append(f"spoof={self.spoof}")
        extras += [f for f, on in (("ack", self.ack), ("oneway", self.oneway)) if on]
        return " ".join([f"{self.src} -> {self.dst} {svc}", *extras])


def _port(text: str, what: str) -> int:
    if not text.isdigit() or not 0 <= int(text) <= 65535:
        raise FlowError(f"{what} must be a port number 0-65535, got {text!r}")
    return int(text)


def _address(text: str, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as exc:
        raise FlowError(f"{what} must be an IPv4 address, got {text!r}") from exc


def parse_flow(text: str) -> FlowSpec:
    """Parse the one-line flow syntax described in the module docstring."""
    m = _LINE.match(str(text).strip())
    if not m:
        raise FlowError(f"cannot read flow {text!r}; expected '<src> -> <dst> <proto>/<port> [options]'")
    proto, _, service = m["proto"].lower().partition("/")
    if proto not in PROTOCOLS:
        raise FlowError(f"{text!r}: protocol must be one of {', '.join(PROTOCOLS)}")
    dport = icmp = None
    if proto == "icmp":
        icmp = service or "echo"
        if icmp not in ICMP_TYPES:
            raise FlowError(f"{text!r}: icmp type must be one of {', '.join(ICMP_TYPES)}")
    else:
        if not service:
            raise FlowError(f"{text!r}: {proto} needs a destination port ({proto}/<port>)")
        dport = _port(service, "destination port")
    sport = spoof = None
    flags: set[str] = set()
    for token in m["rest"].split():
        key, eq, value = token.partition("=")
        if eq:
            if key not in _KEYS:
                raise FlowError(f"{text!r}: unknown option {key!r}; options are {', '.join(sorted(_KEYS))}")
            if key == "sport":
                sport = _port(value, "sport")
            else:
                spoof = _address(value, "spoof")
        elif token in _FLAGS:
            flags.add(token)
        else:
            raise FlowError(f"{text!r}: unknown flag {token!r}; flags are {', '.join(sorted(_FLAGS))}")
    if "ack" in flags and proto != "tcp":
        raise FlowError(f"{text!r}: 'ack' only applies to tcp")
    if sport is not None and proto == "icmp":
        raise FlowError(f"{text!r}: icmp has no source port")
    return FlowSpec(m["src"], m["dst"], proto, dport, sport, icmp, "ack" in flags, spoof, "oneway" in flags)
