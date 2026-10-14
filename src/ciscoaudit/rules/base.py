"""Rule framework: metadata, the ``@rule`` decorator and the registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..model import Evidence, Severity
from ..parser import ConfigLine, DeviceConfig

# Reference documents are named, not linked, so they cannot rot; docs/ lists them with URLs.
REF_CISCO_HARDEN = "Cisco, Harden IOS Devices"
REF_CIS_IOS = "CIS Cisco IOS Benchmark"
REF_NSA_NIG = "NSA, Network Infrastructure Security Guide"
REF_NSA_PWD = "NSA, Cisco Password Types: Best Practices"


def attack(technique_id: str, name: str) -> str:
    return f"MITRE ATT&CK {technique_id} {name}"


ALL_TYPES = ("router", "switch")


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    severity: Severity
    category: str
    risk: str
    remediation: str
    references: tuple[str, ...] = ()
    applies_to: tuple[str, ...] = ALL_TYPES


@dataclass
class Hit:
    """One occurrence of a rule's problem on one device."""

    obj: str  # stable label of the affected object ("vty lines", "global", "interfaces")
    detail: str  # what exactly was found, in plain words
    evidence: list[ConfigLine | Evidence] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)
    severity: Severity | None = None  # overrides the rule default for this hit


CheckFn = Callable[[DeviceConfig], Iterable[Hit]]


@dataclass(frozen=True)
class Rule:
    info: RuleInfo
    check: CheckFn

    @property
    def id(self) -> str:
        return self.info.id


REGISTRY: dict[str, Rule] = {}


def rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    category: str,
    risk: str,
    remediation: str,
    references: tuple[str, ...] = (),
    applies_to: tuple[str, ...] = ALL_TYPES,
) -> Callable[[CheckFn], CheckFn]:
    def register(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        REGISTRY[id] = Rule(RuleInfo(id, title, severity, category, risk, remediation, references, applies_to), fn)
        return fn

    return register


def iface_evidence(interfaces) -> list[ConfigLine]:
    """The ``interface`` stanza line of each interface (range stanzas are listed once)."""
    seen: set[int] = set()
    lines: list[ConfigLine] = []
    for iface in interfaces:
        if iface.line.no not in seen:
            seen.add(iface.line.no)
            lines.append(iface.line)
    return lines
