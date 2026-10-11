"""IOS access-list parsing and packet matching.

Used by two consumers:

* the auditor rules, which look for risky or sloppy entries (``permit ip any any``,
  shadowed rules, ACLs that are referenced but never defined, ...);
* the offline policy simulator, which evaluates concrete packets against the ACLs
  exactly as a router would (first match wins, implicit ``deny ip any any``).

Only IPv4 ACLs are modelled.  Constructs the parser does not understand are kept on
the entry as ``error`` instead of being guessed at.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .parser import ConfigLine, DeviceConfig

MASK32 = 0xFFFFFFFF
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# IP protocol names understood in ACL entries -> protocol number (None = any).
PROTOCOLS: dict[str, int | None] = {
    "ip": None, "icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "udp": 17, "gre": 47,
    "esp": 50, "ahp": 51, "eigrp": 88, "ospf": 89, "nos": 94, "pim": 103, "pcp": 108,
}
_PROTO_BY_NUMBER = {v: k for k, v in PROTOCOLS.items() if v is not None}

_COMMON_PORTS = {"domain": 53, "echo": 7, "discard": 9, "sunrpc": 111, "syslog": 514, "tacacs": 49,
                 "talk": 517, "time": 37, "pim-auto-rp": 496}
TCP_PORT_NAMES: dict[str, int] = {
    **_COMMON_PORTS,
    "bgp": 179, "chargen": 19, "cmd": 514, "daytime": 13, "drip": 3949, "exec": 512, "finger": 79,
    "ftp": 21, "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194, "klogin": 543,
    "kshell": 544, "login": 513, "lpd": 515, "nntp": 119, "pop2": 109, "pop3": 110, "smtp": 25,
    "telnet": 23, "uucp": 540, "whois": 43, "www": 80,
    # not IOS 12.4 keywords, accepted when reading newer or hand-written configs
    "ssh": 22, "https": 443,
}
UDP_PORT_NAMES: dict[str, int] = {
    **_COMMON_PORTS,
    "biff": 512, "bootpc": 68, "bootps": 67, "dnsix": 195, "isakmp": 500, "mobile-ip": 434,
    "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139, "non500-isakmp": 4500,
    "ntp": 123, "rip": 520, "snmp": 161, "snmptrap": 162, "tftp": 69, "who": 513, "xdmcp": 177,
}
PORT_NAMES = {"tcp": TCP_PORT_NAMES, "udp": UDP_PORT_NAMES}

# ICMP keyword -> (type, code or None for "any code")
ICMP_NAMES: dict[str, tuple[int, int | None]] = {
    "echo": (8, None), "echo-reply": (0, None), "unreachable": (3, None), "net-unreachable": (3, 0),
    "host-unreachable": (3, 1), "protocol-unreachable": (3, 2), "port-unreachable": (3, 3),
    "packet-too-big": (3, 4), "administratively-prohibited": (3, 13), "time-exceeded": (11, None),
    "ttl-exceeded": (11, 0), "reassembly-timeout": (11, 1), "redirect": (5, None),
    "parameter-problem": (12, None), "source-quench": (4, None), "timestamp-request": (13, None),
    "timestamp-reply": (14, None), "mask-request": (17, None), "mask-reply": (18, None),
    "information-request": (15, None), "information-reply": (16, None),
    "router-advertisement": (9, None), "router-solicitation": (10, None), "traceroute": (30, None),
    "alternate-address": (6, None), "conversion-error": (31, None), "mobile-redirect": (32, None),
}

_TCP_FLAGS = {"ack", "fin", "psh", "rst", "syn", "urg"}
_OPTION_WITH_ARG = {"time-range", "precedence", "dscp", "tos", "reflect", "evaluate"}


# =============================================================================
# Address and port matchers
# =============================================================================


@dataclass(frozen=True)
class Net:
    """An address plus wildcard mask (set bits are "don't care"), as ACLs use."""

    addr: int
    wild: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "addr", self.addr & ~self.wild & MASK32)

    @classmethod
    def any(cls) -> "Net":
        return cls(0, MASK32)

    @classmethod
    def host(cls, ip: str | ipaddress.IPv4Address) -> "Net":
        return cls(int(ipaddress.IPv4Address(ip)), 0)

    @classmethod
    def from_network(cls, network: str | ipaddress.IPv4Network) -> "Net":
        net = ipaddress.IPv4Network(network, strict=False)
        return cls(int(net.network_address), int(net.hostmask))

    @property
    def is_any(self) -> bool:
        return self.wild == MASK32

    @property
    def is_host(self) -> bool:
        return self.wild == 0

    def contains(self, ip: int | ipaddress.IPv4Address) -> bool:
        value = int(ip)
        return (value ^ self.addr) & ~self.wild & MASK32 == 0

    def covers(self, other: "Net") -> bool:
        """True if every address matched by ``other`` is also matched by ``self``."""
        return (self.wild & other.wild) == other.wild and (self.addr ^ other.addr) & ~self.wild & MASK32 == 0

    def __str__(self) -> str:
        if self.is_any:
            return "any"
        if self.is_host:
            return f"host {ipaddress.IPv4Address(self.addr)}"
        return f"{ipaddress.IPv4Address(self.addr)} {ipaddress.IPv4Address(self.wild)}"


@dataclass(frozen=True)
class PortSet:
    """A set of TCP/UDP ports stored as sorted, merged inclusive ranges."""

    ranges: tuple[tuple[int, int], ...]
    text: str = field(default="", compare=False)

    @classmethod
    def from_ranges(cls, ranges, text: str = "") -> "PortSet":
        merged: list[list[int]] = []
        for lo, hi in sorted(ranges):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        return cls(tuple((lo, hi) for lo, hi in merged), text)

    def contains(self, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self.ranges)

    def covers(self, other: "PortSet") -> bool:
        return all(any(lo <= olo and ohi <= hi for lo, hi in self.ranges) for olo, ohi in other.ranges)

    def __str__(self) -> str:
        return self.text


def _port_value(token: str, proto: str) -> int | None:
    if token.isdigit():
        value = int(token)
        return value if 0 <= value <= 65535 else None
    return PORT_NAMES.get(proto, {}).get(token)


# =============================================================================
# Entries and lists
# =============================================================================


@dataclass(frozen=True)
class Packet:
    """The fields of a packet an ACL can look at."""

    proto: str  # tcp | udp | icmp | ospf | ...
    src: int
    dst: int
    sport: int | None = None
    dport: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    tcp_ack: bool = False  # ACK or RST set: what the ``established`` keyword matches

    @classmethod
    def make(cls, proto: str, src: str, dst: str, **kw) -> "Packet":
        return cls(proto.lower(), int(ipaddress.IPv4Address(src)), int(ipaddress.IPv4Address(dst)), **kw)


@dataclass(eq=False)
class ACE:
    """One access-list entry."""

    line: ConfigLine
    seq: int | None
    action: str  # permit | deny
    proto: str
    src: Net
    dst: Net | None  # None in standard ACLs
    sport: PortSet | None = None
    dport: PortSet | None = None
    icmp: tuple[int, int | None] | None = None
    established: bool = False
    log: bool = False
    flags: frozenset[str] = frozenset()
    options: tuple[str, ...] = ()
    standard: bool = False
    error: str | None = None

    @property
    def text(self) -> str:
        return self.line.text

    @property
    def is_any_any(self) -> bool:
        """``permit ip any any`` (or the standard-ACL equivalent ``permit any``)."""
        plain = not (self.sport or self.dport or self.icmp or self.established or self.flags or self.options)
        if self.standard:
            return self.src.is_any and plain
        return self.proto == "ip" and self.src.is_any and bool(self.dst and self.dst.is_any) and plain

    def matches(self, pkt: Packet) -> bool:
        if self.error:
            return False
        if not self.src.contains(pkt.src):
            return False
        if self.standard:
            return True
        if self.proto != "ip" and self.proto != pkt.proto:
            return False
        if self.dst is not None and not self.dst.contains(pkt.dst):
            return False
        if self.proto in ("tcp", "udp"):
            if self.sport is not None and (pkt.sport is None or not self.sport.contains(pkt.sport)):
                return False
            if self.dport is not None and (pkt.dport is None or not self.dport.contains(pkt.dport)):
                return False
            if self.proto == "tcp" and self.established and not pkt.tcp_ack:
                return False
        if self.proto == "icmp" and self.icmp is not None:
            if pkt.icmp_type != self.icmp[0]:
                return False
            if self.icmp[1] is not None and pkt.icmp_code != self.icmp[1]:
                return False
        return True

    def covers(self, other: "ACE") -> bool:
        """Conservative test: does every packet matched by ``other`` also match ``self``?

        ``False`` negatives are acceptable (never report a shadowed rule that is not
        shadowed); ``True`` is only returned when the containment is certain.
        """
        if self.error or other.error or self.standard != other.standard:
            return False
        if not self.src.covers(other.src):
            return False
        if self.standard:
            return True
        if self.proto != "ip" and self.proto != other.proto:
            return False
        if not (self.dst and other.dst and self.dst.covers(other.dst)):
            return False
        if self.proto in ("tcp", "udp") and self.sport is not None:
            if other.sport is None or not self.sport.covers(other.sport):
                return False
        if self.proto in ("tcp", "udp") and self.dport is not None:
            if other.dport is None or not self.dport.covers(other.dport):
                return False
        if self.proto == "icmp" and self.icmp is not None:
            if other.icmp is None or other.icmp[0] != self.icmp[0]:
                return False
            if self.icmp[1] is not None and other.icmp[1] != self.icmp[1]:
                return False
        if self.established != other.established and self.established:
            return False
        if not self.flags <= other.flags:
            return False
        return not self.options or self.options == other.options


@dataclass(frozen=True)
class Verdict:
    action: str  # permit | deny
    ace: ACE | None  # the entry that decided, None for implicit decisions
    reason: str  # "entry" | "implicit-deny" | "empty-acl-permit"


@dataclass(eq=False)
class ACL:
    name: str
    kind: str  # standard | extended
    numbered: bool
    declaration: ConfigLine
    lines: list[ConfigLine] = field(default_factory=list)
    entries: list[ACE] = field(default_factory=list)
    remarks: list[ConfigLine] = field(default_factory=list)

    def evaluate(self, pkt: Packet) -> Verdict:
        """First match wins; falls off the end into the implicit ``deny ip any any``."""
        if not self.entries:
            # IOS does not filter with an ACL that has no entries.
            return Verdict("permit", None, "empty-acl-permit")
        for ace in self.entries:
            if ace.matches(pkt):
                return Verdict(ace.action, ace, "entry")
        return Verdict("deny", None, "implicit-deny")


# =============================================================================
# Parsing
# =============================================================================


class _Tokens:
    def __init__(self, tokens: list[str]) -> None:
        self.t = tokens
        self.i = 0

    def peek(self, offset: int = 0) -> str | None:
        j = self.i + offset
        return self.t[j] if j < len(self.t) else None

    def take(self) -> str | None:
        tok = self.peek()
        if tok is not None:
            self.i += 1
        return tok

    @property
    def done(self) -> bool:
        return self.i >= len(self.t)


def _parse_net(tok: _Tokens, *, standard: bool) -> Net:
    first = tok.take()
    if first is None:
        raise ValueError("missing address")
    if first == "any":
        return Net.any()
    if first == "host":
        addr = tok.take()
        if addr is None or not _IPV4_RE.match(addr):
            raise ValueError("'host' must be followed by an IPv4 address")
        return Net.host(addr)
    if _IPV4_RE.match(first):
        nxt = tok.peek()
        if nxt is not None and _IPV4_RE.match(nxt):
            tok.take()
            return Net(int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(nxt)))
        if standard:
            return Net.host(first)
        raise ValueError(f"address {first} needs a wildcard mask (or use 'host')")
    raise ValueError(f"unsupported address specification {first!r}")


def _parse_ports(tok: _Tokens, proto: str) -> PortSet | None:
    op = tok.peek()
    if op not in ("eq", "neq", "gt", "lt", "range"):
        return None
    tok.take()
    values: list[int] = []
    raw: list[str] = []
    limit = 2 if op == "range" else (1 if op in ("gt", "lt") else 99)
    while len(values) < limit:
        nxt = tok.peek()
        if nxt is None:
            break
        value = _port_value(nxt, proto)
        if value is None:
            if not values:
                raise ValueError(f"unknown port {nxt!r} for {proto}")
            break
        values.append(value)
        raw.append(nxt)
        tok.take()
    if not values or (op == "range" and len(values) != 2):
        raise ValueError(f"'{op}' needs {'two ports' if op == 'range' else 'a port'}")
    text = f"{op} {' '.join(raw)}"
    if op == "eq":
        return PortSet.from_ranges([(v, v) for v in values], text)
    if op == "neq":
        allowed: list[tuple[int, int]] = []
        prev = 0
        for v in sorted(set(values)):
            if v > prev:
                allowed.append((prev, v - 1))
            prev = v + 1
        if prev <= 65535:
            allowed.append((prev, 65535))
        return PortSet.from_ranges(allowed, text)
    if op == "gt":
        return PortSet.from_ranges([(values[0] + 1, 65535)] if values[0] < 65535 else [], text)
    if op == "lt":
        return PortSet.from_ranges([(0, values[0] - 1)] if values[0] > 0 else [], text)
    lo, hi = sorted(values)
    return PortSet.from_ranges([(lo, hi)], text)


def parse_ace(line: ConfigLine, tokens: list[str], *, standard: bool, seq: int | None = None) -> ACE:
    """Parse one entry (``tokens`` start at permit/deny).  Never raises."""
    placeholder = Net.any()
    action = tokens[0] if tokens else ""
    ace = ACE(line=line, seq=seq, action=action, proto="ip", src=placeholder, dst=None if standard else placeholder,
              standard=standard)
    try:
        if action not in ("permit", "deny"):
            raise ValueError(f"unsupported entry type {action!r}")
        tok = _Tokens(tokens[1:])
        if not standard:
            proto = tok.take()
            if proto is None:
                raise ValueError("missing protocol")
            if proto.isdigit():
                number = int(proto)
                proto = _PROTO_BY_NUMBER.get(number, f"proto-{number}")
            elif proto not in PROTOCOLS:
                raise ValueError(f"unknown protocol {proto!r}")
            ace.proto = proto
        ace.src = _parse_net(tok, standard=standard)
        if not standard:
            if ace.proto in ("tcp", "udp"):
                ace.sport = _parse_ports(tok, ace.proto)
            ace.dst = _parse_net(tok, standard=False)
            if ace.proto in ("tcp", "udp"):
                ace.dport = _parse_ports(tok, ace.proto)
            elif ace.proto == "icmp":
                nxt = tok.peek()
                if nxt is not None and nxt in ICMP_NAMES:
                    ace.icmp = ICMP_NAMES[tok.take()]
                elif nxt is not None and nxt.isdigit():
                    icmp_type = int(tok.take())
                    code_tok = tok.peek()
                    code = int(tok.take()) if code_tok is not None and code_tok.isdigit() else None
                    ace.icmp = (icmp_type, code)
        flags: set[str] = set()
        options: list[str] = []
        while not tok.done:
            word = tok.take()
            if word == "established":
                ace.established = True
            elif word in ("log", "log-input"):
                ace.log = True
            elif word in _TCP_FLAGS:
                flags.add(word)
            elif word == "fragments":
                options.append(word)
            elif word in _OPTION_WITH_ARG:
                arg = tok.take()
                options.append(f"{word} {arg}")
            elif word in ("match-any", "match-all") or (word and word[0] in "+-" and word[1:] in _TCP_FLAGS):
                options.append(word)
            else:
                raise ValueError(f"unsupported keyword {word!r}")
        ace.flags = frozenset(flags)
        ace.options = tuple(options)
    except ValueError as exc:
        ace.error = str(exc)
    return ace


_NUMBERED_RE = re.compile(r"^access-list\s+(\d+)\s+(.*)$", re.IGNORECASE)


def _kind_for_number(number: int) -> str:
    return "standard" if number < 100 or 1300 <= number <= 1999 else "extended"


def _finish(acl: ACL) -> None:
    last = 0
    for ace in acl.entries:
        ace.seq = ace.seq if ace.seq is not None else last + 10
        last = ace.seq
    acl.entries.sort(key=lambda a: a.seq or 0)


def parse_acls(cfg: DeviceConfig) -> dict[str, ACL]:
    """All IPv4 ACLs in a configuration, keyed by name (numbered ACLs by their number)."""
    acls: dict[str, ACL] = {}

    for line in cfg.lines:
        text = line.text
        m = _NUMBERED_RE.match(text)
        if m:
            number, body = m.group(1), m.group(2).split()
            acl = acls.get(number)
            if acl is None:
                acl = acls[number] = ACL(number, _kind_for_number(int(number)), True, line)
            acl.lines.append(line)
            if body and body[0].lower() == "remark":
                acl.remarks.append(line)
            else:
                acl.entries.append(parse_ace(line, [b.lower() for b in body], standard=acl.kind == "standard"))
        elif line.starts("ip", "access-list") and len(line.words) >= 4 and line.words[2] in ("standard", "extended"):
            name = line.text.split()[3]
            acl = acls.get(name)
            if acl is None:
                acl = acls[name] = ACL(name, line.words[2], False, line)
            acl.lines.append(line)
            for child in line.children:
                words = list(child.words)
                seq = None
                if words and words[0].isdigit():
                    seq = int(words[0])
                    words = words[1:]
                if not words:
                    continue
                if words[0] == "remark":
                    acl.remarks.append(child)
                    continue
                acl.entries.append(parse_ace(child, words, standard=acl.kind == "standard", seq=seq))

    for acl in acls.values():
        _finish(acl)
    return acls
