"""Hierarchical parser for Cisco IOS running-configuration text.

The parser turns the flat text of ``show running-config`` (or a configuration written
by hand) into a tree of :class:`ConfigLine` objects and exposes the typed views the
audit rules need: interfaces, ``line`` blocks, local users and banners.  ACLs are
parsed by :mod:`ciscoaudit.acl`.

It is deliberately forgiving - an audit tool that crashes on the first unexpected
line is worse than one that skips it - and it handles on purpose:

* comments (``!``), blank lines and ``show run`` noise (``Building configuration...``);
* multi-line banners with any delimiter character (``^C``, ``#``, ...) whose text is
  never interpreted as configuration;
* ``interface range`` stanzas, expanded to individual interfaces;
* abbreviated interface names (``Fa0/1`` is ``FastEthernet0/1``);
* ``no <command>`` negations, with last-statement-wins semantics.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .model import Evidence, redact


class ConfigError(Exception):
    """Raised when a file cannot be treated as a text configuration at all."""


# =============================================================================
# Lines
# =============================================================================


@dataclass(eq=False)
class ConfigLine:
    """One configuration command plus the indented commands underneath it."""

    no: int  # 1-based line number in the source file
    text: str  # whitespace-normalised command text
    indent: int = 0
    parent: "ConfigLine | None" = field(default=None, repr=False)
    children: list["ConfigLine"] = field(default_factory=list, repr=False)
    extra: str = ""  # free-form payload that is not configuration (banner text)
    words: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.words = tuple(self.text.lower().split())

    # -- matching ------------------------------------------------------------
    def starts(self, *prefix: str) -> bool:
        """True if the command begins with these words (case-insensitive)."""
        return self.words[: len(prefix)] == tuple(p.lower() for p in prefix)

    def rest(self, *prefix: str) -> str:
        """Original-case text that follows ``prefix`` (given as words)."""
        n = len(prefix)
        parts = self.text.split(None, n)
        return parts[n] if len(parts) > n else ""

    @property
    def context(self) -> str | None:
        return self.parent.text if self.parent is not None else None

    def evidence(self) -> Evidence:
        return Evidence(self.no, redact(self.text, self.context), redact(self.context) if self.context else None)

    # -- children ------------------------------------------------------------
    def children_starting(self, *prefix: str) -> list["ConfigLine"]:
        return [c for c in self.children if c.starts(*prefix)]

    def child_starting(self, *prefix: str) -> "ConfigLine | None":
        for c in self.children:
            if c.starts(*prefix):
                return c
        return None

    def has_child(self, *prefix: str) -> bool:
        return self.child_starting(*prefix) is not None

    def child_state(self, *prefix: str) -> tuple[bool | None, "ConfigLine | None"]:
        """Effective state of ``<prefix>`` under this command.

        ``(True, line)`` if enabled, ``(False, line)`` if explicitly negated with
        ``no``, ``(None, None)`` if absent.  The last statement wins.
        """
        return _effective_state(self.children, prefix)

    def walk(self) -> Iterator["ConfigLine"]:
        for c in self.children:
            yield c
            yield from c.walk()


def _effective_state(lines: list[ConfigLine], prefix: tuple[str, ...]) -> tuple[bool | None, ConfigLine | None]:
    p = tuple(x.lower() for x in prefix)
    neg = ("no",) + p
    state: bool | None = None
    hit: ConfigLine | None = None
    for c in lines:
        if c.words[: len(p)] == p:
            state, hit = True, c
        elif c.words[: len(neg)] == neg:
            state, hit = False, c
    return state, hit


# =============================================================================
# Interface names
# =============================================================================

_IF_TYPES = (
    ("fastethernet", "FastEthernet"),
    ("gigabitethernet", "GigabitEthernet"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("ethernet", "Ethernet"),
    ("serial", "Serial"),
    ("loopback", "Loopback"),
    ("tunnel", "Tunnel"),
    ("vlan", "Vlan"),
    ("port-channel", "Port-channel"),
    ("portchannel", "Port-channel"),
    ("null", "Null"),
)
_IFNAME_RE = re.compile(r"^(?P<type>[A-Za-z][A-Za-z-]*?)\s*(?P<num>\d[\d/.:]*)$")


def canon_ifname(name: str) -> str:
    """``Fa0/1`` -> ``FastEthernet0/1`` (IOS accepts any unambiguous abbreviation)."""
    m = _IFNAME_RE.match(name.strip())
    if not m:
        return name.strip()
    kind = m.group("type").lower()
    for full, canon in _IF_TYPES:
        if full.startswith(kind):
            return canon + m.group("num")
    return m.group("type") + m.group("num")


_SEG_RE = re.compile(
    r"^(?P<type>[A-Za-z][A-Za-z-]*?)\s*(?P<s>\d+(?:/\d+)*)"
    r"(?:\s*-\s*(?:(?P<type2>[A-Za-z][A-Za-z-]*?)\s*)?(?P<e>\d+(?:/\d+)*))?$"
)


def expand_range(spec: str) -> list[str] | None:
    """Expand ``FastEthernet0/1 - 24, Gi0/1 - 2`` into canonical interface names.

    Returns ``None`` if the range cannot be understood.
    """
    names: list[str] = []
    last_type: str | None = None
    for seg in spec.split(","):
        seg = seg.strip()
        if not seg:
            continue
        if seg[0].isdigit() and last_type:
            seg = last_type + seg
        m = _SEG_RE.match(seg)
        if not m:
            return None
        kind = m.group("type")
        last_type = kind
        start_parts = m.group("s").split("/")
        base = "".join(p + "/" for p in start_parts[:-1])
        first = int(start_parts[-1])
        if m.group("e") is None:
            names.append(canon_ifname(f"{kind}{base}{first}"))
            continue
        end_parts = m.group("e").split("/")
        if len(end_parts) > 1 and "".join(p + "/" for p in end_parts[:-1]) != base:
            return None
        last = int(end_parts[-1])
        if last < first or last - first > 512:
            return None
        names.extend(canon_ifname(f"{kind}{base}{n}") for n in range(first, last + 1))
    return names or None


# =============================================================================
# Typed views
# =============================================================================


@dataclass(eq=False)
class Interface:
    """One interface, merged from every stanza that configures it."""

    name: str  # canonical, e.g. "FastEthernet0/1"
    stanzas: list[ConfigLine]  # "interface ..." lines (a range stanza can serve many interfaces)

    @property
    def line(self) -> ConfigLine:
        return self.stanzas[0]

    @property
    def commands(self) -> list[ConfigLine]:
        return [c for s in self.stanzas for c in s.children]

    @property
    def kind(self) -> str:
        n = self.name.lower()
        if n.startswith("vlan"):
            return "svi"
        if n.startswith("loopback"):
            return "loopback"
        if n.startswith("tunnel"):
            return "tunnel"
        if n.startswith("port-channel"):
            return "portchannel"
        if n.startswith("range-macro"):
            return "other"
        if "." in n:
            return "subinterface"
        return "physical"

    # -- command lookups -----------------------------------------------------
    def state(self, *prefix: str) -> tuple[bool | None, ConfigLine | None]:
        return _effective_state(self.commands, prefix)

    def has(self, *prefix: str) -> bool:
        return self.state(*prefix)[0] is True

    def get(self, *prefix: str) -> ConfigLine | None:
        """Last positive ``<prefix> ...`` command, ``None`` if absent or negated."""
        state, line = self.state(*prefix)
        return line if state else None

    def all(self, *prefix: str) -> list[ConfigLine]:
        p = tuple(x.lower() for x in prefix)
        return [c for c in self.commands if c.words[: len(p)] == p]

    @property
    def shutdown(self) -> bool:
        return self.state("shutdown")[0] is True

    @property
    def description(self) -> str:
        line = self.get("description")
        return line.rest("description") if line else ""

    # -- layer 3 -------------------------------------------------------------
    @property
    def ip(self) -> ipaddress.IPv4Interface | None:
        """Primary IPv4 address, ``None`` if unset, negated or DHCP-assigned."""
        current: ipaddress.IPv4Interface | None = None
        for c in self.commands:
            if c.starts("no", "ip", "address") and "secondary" not in c.words:
                current = None
            elif c.starts("ip", "address", "dhcp"):
                current = None
            elif c.starts("ip", "address") and len(c.words) >= 4 and "secondary" not in c.words:
                try:
                    current = ipaddress.IPv4Interface(f"{c.words[2]}/{c.words[3]}")
                except ValueError:
                    current = None
        return current

    @property
    def access_groups(self) -> dict[str, tuple[str, ConfigLine]]:
        """``{"in": (acl_name, line), "out": (...)}`` for ``ip access-group``."""
        out: dict[str, tuple[str, ConfigLine]] = {}
        for c in self.commands:
            if c.starts("ip", "access-group") and len(c.words) >= 4 and c.words[3] in ("in", "out"):
                out[c.words[3]] = (c.text.split()[2], c)
            elif c.starts("no", "ip", "access-group") and len(c.words) >= 5 and c.words[4] in ("in", "out"):
                out.pop(c.words[4], None)
        return out

    # -- layer 2 -------------------------------------------------------------
    @property
    def explicit_mode(self) -> str | None:
        """``access`` / ``trunk`` / ``dynamic-auto`` / ``dynamic-desirable`` / ``routed`` / ``None``."""
        routed = False
        for c in self.commands:
            if c.words == ("no", "switchport"):
                routed = True
            elif c.words == ("switchport",):
                routed = False
        if routed:
            return "routed"
        line = self.get("switchport", "mode")
        if line is None or len(line.words) < 3:
            return None
        if line.words[2] == "access":
            return "access"
        if line.words[2] == "trunk":
            return "trunk"
        if line.words[2] == "dynamic":
            return "dynamic-desirable" if line.words[3:4] == ("desirable",) else "dynamic-auto"
        return line.words[2]

    def vlan_list(self, *prefix: str) -> str | None:
        line = self.get(*prefix)
        return line.rest(*prefix) if line else None


@dataclass(eq=False)
class LineBlock:
    """A ``line con 0`` / ``line aux 0`` / ``line vty 0 4`` stanza."""

    kind: str  # con | aux | vty | tty
    first: int
    last: int
    stanza: ConfigLine

    @property
    def label(self) -> str:
        return self.stanza.text

    @property
    def login(self) -> tuple[str, ConfigLine | None]:
        """``local`` | ``aaa`` | ``password`` | ``none`` (explicit ``no login``) | ``unset``."""
        mode, hit = "unset", None
        for c in self.stanza.children:
            if c.words == ("login",):
                mode, hit = "password", c
            elif c.words == ("login", "local"):
                mode, hit = "local", c
            elif c.starts("login", "authentication"):
                mode, hit = "aaa", c
            elif c.words == ("no", "login"):
                mode, hit = "none", c
            elif c.starts("login"):
                mode, hit = "other", c
        return mode, hit

    @property
    def password(self) -> tuple[int | None, str, ConfigLine] | None:
        """``(encryption_type, value, line)`` of the line password, if any."""
        found = None
        for c in self.stanza.children:
            if c.starts("password") and len(c.words) >= 2:
                parts = c.text.split()
                if len(parts) >= 3 and parts[1].isdigit() and len(parts[1]) == 1:
                    found = (int(parts[1]), parts[2], c)
                else:
                    found = (None, parts[1], c)
        return found

    @property
    def transport_input(self) -> tuple[frozenset[str], ConfigLine] | None:
        found = None
        for c in self.stanza.children:
            if c.starts("transport", "input"):
                found = (frozenset(c.words[2:]), c)
        return found

    @property
    def access_class_in(self) -> tuple[str, ConfigLine] | None:
        found = None
        for c in self.stanza.children:
            if c.starts("access-class") and len(c.words) >= 2:
                direction = c.words[2] if len(c.words) > 2 else "in"
                if direction == "in":
                    found = (c.text.split()[1], c)
            elif c.starts("no", "access-class"):
                found = None
        return found

    @property
    def exec_timeout_seconds(self) -> tuple[int, ConfigLine] | None:
        found = None
        for c in self.stanza.children:
            if c.starts("exec-timeout") and len(c.words) >= 2 and c.words[1].isdigit():
                seconds = int(c.words[2]) if len(c.words) > 2 and c.words[2].isdigit() else 0
                found = (int(c.words[1]) * 60 + seconds, c)
        return found

    @property
    def exec_disabled(self) -> bool:
        return self.stanza.child_state("exec")[0] is False


@dataclass(frozen=True)
class UserEntry:
    name: str
    privilege: int | None
    kind: str  # secret | password | nopassword | none
    enc_type: int | None
    value: str | None
    line: ConfigLine


_USER_CRED_RE = re.compile(r"\b(?P<kind>secret|password)\s+(?:(?P<type>\d)\s+)?(?P<value>\S+)", re.I)
_USER_PRIV_RE = re.compile(r"\bprivilege\s+(?P<lvl>\d+)", re.I)


# =============================================================================
# Device configuration
# =============================================================================

_SWITCH_MODEL_RE = re.compile(r"(2950|2960|2970|3560|3650|3750|3850|9[2345]00|catalyst|ws-c)", re.I)
_ROUTER_MODEL_RE = re.compile(r"\b(1[789]\d\d|2[68]\d\d|29(?:01|11|21|51)|3[89](?:25|45)|8\d\d|isr|asr|csr)", re.I)
_MODEL_HINT_RE = re.compile(r"\bcisco\s+(?P<model>[A-Za-z]{0,4}-?\d{3,4}[A-Za-z0-9-]*)", re.I)

_NOISE_RE = re.compile(
    r"^(?:building configuration\.\.\.|current configuration\s*:|using\s+\d+\s+out\s+of\s+\d+\s+bytes"
    r"|\S+[#>]\s*(?:show|sh)\s+\S+)",
    re.I,
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(eq=False)
class DeviceConfig:
    """A parsed device configuration."""

    path: str
    name: str  # identifier used in reports (file stem, else hostname)
    lines: list[ConfigLine]
    comments: list[tuple[int, str]]
    total_lines: int
    warnings: list[str] = field(default_factory=list)
    hostname: str | None = None
    ios_version: str | None = None
    model: str | None = None
    device_type: str = "unknown"  # router | switch | unknown
    _cache: dict = field(default_factory=dict, repr=False)

    # -- generic access ------------------------------------------------------
    def walk(self) -> Iterator[ConfigLine]:
        for line in self.lines:
            yield line
            yield from line.walk()

    def top(self, *prefix: str) -> list[ConfigLine]:
        p = tuple(x.lower() for x in prefix)
        return [l for l in self.lines if l.words[: len(p)] == p]

    def top_one(self, *prefix: str) -> ConfigLine | None:
        found = self.top(*prefix)
        return found[0] if found else None

    def state(self, *prefix: str) -> tuple[bool | None, ConfigLine | None]:
        """Effective state of a global command (see :meth:`ConfigLine.child_state`)."""
        return _effective_state(self.lines, prefix)

    @property
    def is_router(self) -> bool:
        return self.device_type == "router"

    @property
    def is_switch(self) -> bool:
        return self.device_type == "switch"

    # -- views ----------------------------------------------------------------
    @property
    def interfaces(self) -> list[Interface]:
        if "interfaces" not in self._cache:
            self._cache["interfaces"] = _build_interfaces(self)
        return self._cache["interfaces"]

    def interface(self, name: str) -> Interface | None:
        wanted = canon_ifname(name)
        for iface in self.interfaces:
            if iface.name.lower() == wanted.lower():
                return iface
        return None

    @property
    def line_blocks(self) -> list[LineBlock]:
        if "lines" not in self._cache:
            self._cache["lines"] = _build_line_blocks(self)
        return self._cache["lines"]

    def lines_of(self, kind: str) -> list[LineBlock]:
        return [b for b in self.line_blocks if b.kind == kind]

    @property
    def users(self) -> list[UserEntry]:
        if "users" not in self._cache:
            self._cache["users"] = _build_users(self)
        return self._cache["users"]

    @property
    def banners(self) -> dict[str, ConfigLine]:
        if "banners" not in self._cache:
            found: dict[str, ConfigLine] = {}
            for line in self.lines:
                if line.words[:1] == ("banner",) and len(line.words) >= 2:
                    found[line.words[1]] = line
            self._cache["banners"] = found
        return self._cache["banners"]

    @property
    def acls(self):  # -> dict[str, ciscoaudit.acl.ACL]
        if "acls" not in self._cache:
            from .acl import parse_acls  # local import: acl depends on this module

            self._cache["acls"] = parse_acls(self)
        return self._cache["acls"]

    @property
    def routing_processes(self) -> list[ConfigLine]:
        return [l for l in self.lines if l.words[:1] == ("router",) and len(l.words) >= 2]

    @property
    def label(self) -> str:
        """Display name: the identifier, plus the hostname when it differs."""
        if self.hostname and self.hostname != self.name:
            return f"{self.name} (hostname {self.hostname})"
        return self.name


def _build_interfaces(cfg: DeviceConfig) -> list[Interface]:
    by_name: dict[str, Interface] = {}
    order: list[Interface] = []

    def add(name: str, stanza: ConfigLine) -> None:
        key = name.lower()
        if key not in by_name:
            by_name[key] = Interface(name=name, stanzas=[])
            order.append(by_name[key])
        by_name[key].stanzas.append(stanza)

    for line in cfg.lines:
        if line.words[:1] != ("interface",) or len(line.words) < 2:
            continue
        if line.words[1] == "range":
            spec = line.rest("interface", "range")
            if spec.lower().startswith("macro"):
                cfg.warnings.append(f"line {line.no}: 'interface range macro' cannot be expanded")
                add("range-macro:" + spec.split(None, 1)[-1], line)
                continue
            names = expand_range(spec)
            if names is None:
                cfg.warnings.append(f"line {line.no}: cannot expand interface range {spec!r}")
                continue
            for n in names:
                add(n, line)
        else:
            add(canon_ifname(line.rest("interface")), line)
    return order


def _build_line_blocks(cfg: DeviceConfig) -> list[LineBlock]:
    blocks: list[LineBlock] = []
    for line in cfg.top("line"):
        w = line.words
        if len(w) < 2:
            continue
        kind = {"con": "con", "console": "con", "aux": "aux", "vty": "vty"}.get(w[1], "tty")
        nums = [int(x) for x in w[1:] if x.isdigit()]
        first = nums[0] if nums else 0
        last = nums[1] if len(nums) > 1 else first
        blocks.append(LineBlock(kind=kind, first=first, last=last, stanza=line))
    return blocks


def _build_users(cfg: DeviceConfig) -> list[UserEntry]:
    users: list[UserEntry] = []
    for line in cfg.top("username"):
        if len(line.words) < 2:
            continue
        name = line.text.split()[1]
        priv_m = _USER_PRIV_RE.search(line.text)
        priv = int(priv_m.group("lvl")) if priv_m else None
        cred = _USER_CRED_RE.search(line.text)
        if cred:
            enc = cred.group("type")
            users.append(UserEntry(name, priv, cred.group("kind").lower(), int(enc) if enc else None,
                                   cred.group("value"), line))
        elif "nopassword" in line.words:
            users.append(UserEntry(name, priv, "nopassword", None, None, line))
        else:
            users.append(UserEntry(name, priv, "none", None, None, line))
    return users


# =============================================================================
# Parsing
# =============================================================================


def _detect_model(cfg: DeviceConfig) -> str | None:
    for _no, text in cfg.comments[:25]:
        m = _MODEL_HINT_RE.search(text)
        if m:
            return m.group("model")
    return None


def _guess_device_type(cfg: DeviceConfig) -> str:
    hint = " ".join(t for _n, t in cfg.comments[:25])
    if cfg.model:
        if _SWITCH_MODEL_RE.search(cfg.model):
            return "switch"
        if _ROUTER_MODEL_RE.search(cfg.model):
            return "router"
    elif hint:
        if _SWITCH_MODEL_RE.search(hint) and not _ROUTER_MODEL_RE.search(hint):
            return "switch"
    # Content-based fallback.  Packet Tracer routers also print "spanning-tree mode"
    # and "interface Vlan1", so routing evidence is checked first.
    ifaces = cfg.interfaces
    if cfg.routing_processes or cfg.top("ip", "classless") or cfg.top("ip", "flow-export"):
        return "router"
    if any(i.kind in ("physical", "subinterface") and i.ip for i in ifaces):
        return "router"
    if any(i.all("switchport") for i in ifaces):
        return "switch"
    if cfg.top("spanning-tree") or any(i.kind == "svi" for i in ifaces):
        return "switch"
    return "unknown"


def parse_config(text: str, path: str = "<memory>", *, name: str | None = None) -> DeviceConfig:
    """Parse configuration text into a :class:`DeviceConfig` (never raises on odd lines)."""
    raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x03", "^C").split("\n")
    top: list[ConfigLine] = []
    comments: list[tuple[int, str]] = []
    stack: list[ConfigLine] = []
    warnings: list[str] = []

    i, n = 0, len(raw_lines)
    while i < n:
        no = i + 1
        line = _CTRL_RE.sub("", raw_lines[i]).rstrip()
        stripped = line.strip()
        i += 1
        if not stripped:
            continue
        if stripped.startswith("!"):
            comments.append((no, stripped))
            continue
        if _NOISE_RE.match(stripped):
            continue
        if stripped.lower() == "end":
            break

        indent = len(line) - len(line.lstrip())
        node = ConfigLine(no=no, text=" ".join(stripped.split()), indent=indent)

        banner = re.match(r"^banner\s+(\S+)\s*(.*)$", stripped, re.IGNORECASE) if indent == 0 else None
        if banner:
            kind, rest = banner.group(1), banner.group(2)
            delim = "^C" if rest.startswith("^C") else (rest[0] if rest else "")
            if delim:
                body = rest[len(delim):]
                end = body.find(delim)
                if end != -1:
                    node.extra = body[:end]
                else:
                    collected = [body]
                    closed = False
                    while i < n:
                        nxt = _CTRL_RE.sub("", raw_lines[i])
                        i += 1
                        pos = nxt.find(delim)
                        if pos != -1:
                            collected.append(nxt[:pos])
                            closed = True
                            break
                        collected.append(nxt)
                    if not closed:
                        warnings.append(f"line {no}: banner {kind} is not terminated")
                    node.extra = "\n".join(collected).strip("\n")
                node.text = f"banner {kind.lower()}"
                node.words = tuple(node.text.split())

        while stack and stack[-1].indent >= indent:
            stack.pop()
        if stack:
            node.parent = stack[-1]
            stack[-1].children.append(node)
        else:
            top.append(node)
        stack.append(node)

    cfg = DeviceConfig(
        path=path,
        name=name or "device",
        lines=top,
        comments=comments,
        total_lines=n,
        warnings=warnings,
    )
    host = cfg.top_one("hostname")
    cfg.hostname = host.rest("hostname") if host else None
    ver = cfg.top_one("version")
    cfg.ios_version = ver.rest("version") if ver else None
    cfg.model = _detect_model(cfg)
    cfg.device_type = _guess_device_type(cfg)
    if name is None:
        cfg.name = cfg.hostname or "device"
    return cfg


def load_config(path: str | Path, name: str | None = None) -> DeviceConfig:
    """Read and parse a configuration file; the file stem becomes the device name."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{path}: {exc.strerror or exc}") from exc
    if b"\x00" in data[:4096]:
        raise ConfigError(f"{path}: looks like a binary file, not a text configuration")
    text = data.decode("utf-8-sig", errors="replace")
    return parse_config(text, path=str(path), name=name or p.stem)
