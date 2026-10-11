"""Access-list quality rules (ACL-*)."""

from __future__ import annotations

from ..model import Severity
from ..parser import ConfigLine, DeviceConfig
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG, Hit, attack, rule

_NUMERIC_CONTEXT = {"access-group", "access-class", "list", "address", "distribute-list", "snmp-server", "nat", "match", "class"}


def _root(line: ConfigLine) -> ConfigLine:
    while line.parent is not None:
        line = line.parent
    return line


def references(cfg: DeviceConfig, name: str) -> list[ConfigLine]:
    """Every configuration line (outside ACL definitions) that mentions ACL ``name``."""
    out = []
    for line in cfg.walk():
        root = _root(line)
        if root.starts("access-list") or root.starts("ip", "access-list"):
            continue
        tokens = line.text.split()
        if name not in tokens:
            continue
        if name.isdigit() and not (_NUMERIC_CONTEXT & set(line.words)):
            continue
        out.append(line)
    return out


def applications(cfg: DeviceConfig) -> list[tuple[str, ConfigLine, str]]:
    """``(acl_name, line, where)`` for interface ``ip access-group`` and line ``access-class``."""
    found = []
    for iface in cfg.interfaces:
        for direction, (name, line) in iface.access_groups.items():
            found.append((name, line, f"{iface.name} {direction}"))
    for blk in cfg.line_blocks:
        ac = blk.access_class_in
        if ac:
            found.append((ac[0], ac[1], blk.label))
    return found


@rule(
    id="ACL-001",
    title="ACL contains a 'permit any any' entry",
    severity=Severity.HIGH,
    category="Access lists",
    risk=(
        "An unrestricted permit turns an ACL into a blocklist: everything not explicitly denied above it is allowed, "
        "including new services, spoofed sources and lateral movement. As the first matching entry it disables the ACL."
    ),
    remediation="Replace it with the specific flows that are needed and finish with an explicit 'deny ip any any log'.",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
)
def permit_any_any(cfg: DeviceConfig):
    for name, acl in cfg.acls.items():
        if not references(cfg, name):
            continue  # an unused ACL has no effect; ACL-005 reports it
        deny_seen = False
        for ace in acl.entries:
            if ace.error:
                continue
            if ace.action == "deny" and not ace.is_any_any:
                deny_seen = True
            if ace.action == "permit" and ace.is_any_any:
                yield Hit(
                    obj=f"ACL {name}",
                    detail=(f"'{ace.text}' permits all traffic"
                            + (" after some deny entries (blocklist style)." if deny_seen
                               else " and nothing is denied before it, so the ACL filters nothing.")),
                    evidence=[ace.line],
                    affected=[f"{name} seq {ace.seq}"],
                    severity=Severity.MEDIUM if deny_seen else Severity.HIGH,
                )


@rule(
    id="ACL-002",
    title="Interface ACL does not end with a logged 'deny ip any any'",
    severity=Severity.LOW,
    category="Access lists",
    risk=(
        "Packets dropped by the implicit deny at the end of an ACL are never logged, so scans and policy violations "
        "stay invisible to monitoring."
    ),
    remediation="End every interface ACL with 'deny ip any any log' (mind log rate limits on busy interfaces).",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
)
def no_final_logged_deny(cfg: DeviceConfig):
    seen: set[str] = set()
    for name, _line, where in applications(cfg):
        acl = cfg.acls.get(name)
        if acl is None or name in seen or acl.kind != "extended" or not acl.entries:
            continue
        seen.add(name)
        last = acl.entries[-1]
        if last.action == "deny" and last.is_any_any and last.log:
            continue
        if last.action == "deny" and last.is_any_any:
            detail = f"ACL {name} ends with '{last.text}' but does not log the drops."
        else:
            detail = f"ACL {name} has no explicit final 'deny ip any any'; drops rely on the silent implicit deny."
        yield Hit(obj=f"ACL {name}", detail=detail, evidence=[last.line], affected=[where])


@rule(
    id="ACL-003",
    title="ACL permits Telnet",
    severity=Severity.HIGH,
    category="Access lists",
    risk="Permitting TCP/23 allows clear-text remote administration across the network, exposing credentials to sniffing.",
    remediation="Remove the entry; permit SSH (TCP/22) from the admin host only.",
    references=(attack("T1040", "Network Sniffing"), REF_CIS_IOS),
)
def permit_telnet(cfg: DeviceConfig):
    bad = []
    for name, acl in cfg.acls.items():
        for ace in acl.entries:
            if (not ace.error and ace.action == "permit" and ace.proto == "tcp" and ace.dport is not None
                    and ace.dport.ranges == ((23, 23),)):
                bad.append((name, ace))
    if bad:
        yield Hit(obj="ACLs", detail=f"{len(bad)} entr{'y' if len(bad) == 1 else 'ies'} permit TCP/23.",
                  evidence=[a.line for _, a in bad], affected=[f"{n} seq {a.seq}" for n, a in bad])


@rule(
    id="ACL-004",
    title="ACL is applied but not defined",
    severity=Severity.HIGH,
    category="Access lists",
    risk=(
        "IOS does not filter when the ACL named on an interface or line does not exist, so the interface or VTY line "
        "is silently wide open. A typo in the ACL name is enough."
    ),
    remediation="Define the ACL (or correct the name) and verify with 'show ip interface' and 'show access-lists'.",
    references=(REF_CISCO_HARDEN,),
)
def undefined_acl(cfg: DeviceConfig):
    bad = [(n, l, w) for n, l, w in applications(cfg) if n not in cfg.acls]
    if bad:
        yield Hit(
            obj="ACL references",
            detail="Referenced but never defined: " + ", ".join(f"{n} ({w})" for n, _l, w in bad) + ".",
            evidence=[l for _n, l, _w in bad],
            affected=sorted({n for n, _l, _w in bad}),
        )


@rule(
    id="ACL-005",
    title="ACL is defined but never applied",
    severity=Severity.LOW,
    category="Access lists",
    risk="A dead ACL gives operators the false impression that traffic is filtered; it also hides stale policy.",
    remediation="Apply the ACL where it is meant to act, or delete it.",
    references=(REF_CISCO_HARDEN,),
)
def unused_acl(cfg: DeviceConfig):
    unused = [name for name in cfg.acls if not references(cfg, name)]
    if unused:
        yield Hit(obj="ACLs", detail="No reference found for: " + ", ".join(unused) + ".",
                  evidence=[cfg.acls[n].declaration for n in unused], affected=unused)


@rule(
    id="ACL-006",
    title="ACL entry is shadowed by an earlier entry",
    severity=Severity.LOW,
    category="Access lists",
    risk=(
        "An entry that can never match is dead policy: the rule the author intended is not enforced and the ACL behaves "
        "differently from how it reads."
    ),
    remediation="Reorder so the specific entry comes first, or remove the redundant one.",
    references=(REF_CISCO_HARDEN,),
)
def shadowed_entries(cfg: DeviceConfig):
    for name, acl in cfg.acls.items():
        notes, evidence, affected = [], [], []
        for j, later in enumerate(acl.entries):
            for earlier in acl.entries[:j]:
                if earlier.covers(later):
                    kind = "redundant" if earlier.action == later.action else "contradicted"
                    notes.append(f"seq {later.seq} is {kind} by seq {earlier.seq}")
                    evidence += [later.line, earlier.line]
                    affected.append(f"{name} seq {later.seq}")
                    break
        if notes:
            yield Hit(obj=f"ACL {name}", detail="; ".join(notes) + ".", evidence=evidence[:8], affected=affected)


@rule(
    id="ACL-007",
    title="Router applies no ACL on any routed interface",
    severity=Severity.MEDIUM,
    category="Access lists",
    risk=(
        "With no traffic filtering every attached segment can reach every other: there are no security zones, and one "
        "compromised host can scan and attack the whole network."
    ),
    remediation="Define zone policy ACLs and apply them with 'ip access-group <name> in' on the interface closest to the source.",
    references=(REF_NSA_NIG, REF_CISCO_HARDEN),
    applies_to=("router",),
)
def no_filtering(cfg: DeviceConfig):
    routed = [i for i in cfg.interfaces if i.ip and not i.shutdown and i.kind != "loopback"]
    if len(routed) >= 2 and not any(i.access_groups for i in cfg.interfaces):
        yield Hit(obj="interfaces", detail=f"{len(routed)} routed interfaces, none with 'ip access-group'.",
                  affected=[i.name for i in routed])


@rule(
    id="ACL-008",
    title="ACL entry uses syntax the auditor does not understand",
    severity=Severity.INFO,
    category="Access lists",
    risk="Entries that cannot be parsed are ignored by the auditor and the policy simulator, so their effect is not assessed.",
    remediation="Review the entry manually, or extend the ACL parser if the syntax is valid IOS.",
)
def unparsed_entries(cfg: DeviceConfig):
    for name, acl in cfg.acls.items():
        bad = [e for e in acl.entries if e.error]
        if bad:
            yield Hit(obj=f"ACL {name}", detail="; ".join(f"'{e.text}' ({e.error})" for e in bad) + ".",
                      evidence=[e.line for e in bad], affected=[f"{name} seq {e.seq}" for e in bad])
