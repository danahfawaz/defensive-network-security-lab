"""Remote-access and management-plane rules (AUTH-*, MGMT-*)."""

from __future__ import annotations

from ..model import Severity
from ..parser import DeviceConfig, LineBlock
from .base import (
    REF_CIS_IOS,
    REF_CISCO_HARDEN,
    REF_NSA_NIG,
    Hit,
    attack,
    rule,
)

_REMOTE_ATTACK = attack("T1021.004", "Remote Services: SSH")


def _aaa_default_login(cfg: DeviceConfig) -> bool:
    """True when AAA supplies a default login method (so a bare line still authenticates)."""
    return bool(cfg.state("aaa", "new-model")[0]) and any(
        l.starts("aaa", "authentication", "login", "default") for l in cfg.lines
    )


def _vty(cfg: DeviceConfig) -> list[LineBlock]:
    return cfg.lines_of("vty")


# ---------------------------------------------------------------------------
# AUTH - who may log in
# ---------------------------------------------------------------------------


@rule(
    id="AUTH-001",
    title="VTY lines accept remote logins without authentication",
    severity=Severity.CRITICAL,
    category="Access control",
    risk=(
        "'no login' on a VTY line gives an exec shell to anyone who can reach the device over the network. "
        "Together with a missing or weak enable secret this is complete device takeover with no credentials at all."
    ),
    remediation=(
        "Require authentication on every VTY line: create per-user accounts "
        "('username <name> privilege 15 secret <strong-secret>') and use 'login local' under 'line vty 0 15', "
        "or point 'login authentication' at an AAA method list."
    ),
    references=(attack("T1078", "Valid Accounts"), REF_CISCO_HARDEN, REF_CIS_IOS),
)
def vty_no_authentication(cfg: DeviceConfig):
    blocks = [(b, b.login[1]) for b in _vty(cfg) if b.login[0] == "none"]
    if blocks:
        yield Hit(
            obj="vty lines",
            detail="'no login' is configured, so remote sessions are accepted without any credentials: "
            + ", ".join(b.label for b, _ in blocks) + ".",
            evidence=[line for _, line in blocks],
            affected=[b.label for b, _ in blocks],
        )


@rule(
    id="AUTH-002",
    title="Console or AUX line has no authentication",
    severity=Severity.MEDIUM,
    category="Access control",
    risk=(
        "A line without 'login' gives an unauthenticated exec session to anyone with physical access, a serial "
        "console server or a modem on the AUX port. Out-of-band paths bypass every network-based control."
    ),
    remediation=(
        "Console: 'line con 0' / 'login local' / 'exec-timeout 5 0' / 'logging synchronous'. "
        "AUX: disable it ('line aux 0' / 'no exec' / 'transport input none') unless a modem is genuinely required."
    ),
    references=(REF_CISCO_HARDEN, REF_CIS_IOS),
)
def console_no_authentication(cfg: DeviceConfig):
    bad = []
    for blk in cfg.lines_of("con") + cfg.lines_of("aux"):
        if blk.kind == "aux" and (blk.exec_disabled or _transport_none(blk)):
            continue
        mode, line = blk.login
        if mode == "none" or (mode == "unset" and not _aaa_default_login(cfg)):
            bad.append((blk, line))
    if bad:
        yield Hit(
            obj="console/aux lines",
            detail="No 'login' method is configured on: " + ", ".join(b.label for b, _ in bad) + ".",
            evidence=[line or blk.stanza for blk, line in bad],
            affected=[b.label for b, _ in bad],
        )


@rule(
    id="AUTH-003",
    title="VTY lines use one shared line password instead of per-user accounts",
    severity=Severity.MEDIUM,
    category="Access control",
    risk=(
        "A single password shared by every administrator leaves no per-person audit trail, cannot be revoked for one "
        "person without changing it for all, and is easy to guess, share or leak."
    ),
    remediation="Use 'login local' with one 'username ... secret ...' per administrator (or AAA with TACACS+/RADIUS).",
    references=(REF_CISCO_HARDEN, REF_NSA_NIG),
)
def vty_shared_password(cfg: DeviceConfig):
    blocks = [b for b in _vty(cfg) if b.login[0] == "password" and b.password is not None]
    if blocks:
        yield Hit(
            obj="vty lines",
            detail="A line password is used for authentication on: " + ", ".join(b.label for b in blocks) + ".",
            evidence=[b.login[1] for b in blocks] + [b.password[2] for b in blocks],
            affected=[b.label for b in blocks],
        )


@rule(
    id="AUTH-004",
    title="Line requires a password but none is configured",
    severity=Severity.LOW,
    category="Access control",
    risk=(
        "'login' without a line password makes IOS reject every attempt ('Password required, but none set'). The line "
        "is unusable, and the usual quick fix - adding one shared password - is weaker than per-user authentication."
    ),
    remediation="Switch the line to 'login local' and create per-user accounts with 'username ... secret ...'.",
    references=(REF_CISCO_HARDEN,),
)
def login_without_password(cfg: DeviceConfig):
    blocks = [b for b in cfg.lines_of("vty") + cfg.lines_of("con") + cfg.lines_of("aux")
              if b.login[0] == "password" and b.password is None]
    if blocks:
        yield Hit(
            obj="lines without credentials",
            detail="'login' is set but no 'password' exists on: " + ", ".join(b.label for b in blocks) + ".",
            evidence=[b.login[1] for b in blocks],
            affected=[b.label for b in blocks],
        )


def _transport_none(blk: LineBlock) -> bool:
    ti = blk.transport_input
    return bool(ti) and ti[0] == frozenset({"none"})


# ---------------------------------------------------------------------------
# MGMT - management-plane exposure
# ---------------------------------------------------------------------------


@rule(
    id="MGMT-001",
    title="Telnet is accepted for remote management",
    severity=Severity.HIGH,
    category="Management plane",
    risk=(
        "Telnet sends credentials and every command in clear text. Anyone on the path - or an attacker who can sniff or "
        "ARP-spoof the segment - captures the administrator's password and can replay the session."
    ),
    remediation="Allow only SSH on the VTY lines: 'line vty 0 15' / 'transport input ssh'.",
    references=(attack("T1040", "Network Sniffing"), REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
)
def telnet_allowed(cfg: DeviceConfig):
    bad, evidence = [], []
    for blk in _vty(cfg):
        ti = blk.transport_input
        if ti is None:
            bad.append(blk.label + " (no 'transport input': IOS default accepts Telnet)")
            evidence.append(blk.stanza)
        elif ti[0] & {"telnet", "all"}:
            bad.append(f"{blk.label} ('{ti[1].text}')")
            evidence.append(ti[1])
    if bad:
        yield Hit(obj="vty lines", detail="Telnet is permitted on: " + "; ".join(bad) + ".", evidence=evidence,
                  affected=[b.split(" (")[0] for b in bad])


@rule(
    id="MGMT-002",
    title="VTY access is not restricted to management hosts",
    severity=Severity.MEDIUM,
    category="Management plane",
    risk=(
        "Without an 'access-class', every host that can route to any interface of the device may attempt to log in or "
        "exploit the management services. A management ACL shrinks that audience to a few administrator addresses."
    ),
    remediation=(
        "Define 'ip access-list standard VTY-MGMT' permitting only the admin host(s) and a final 'deny any log', then "
        "apply 'access-class VTY-MGMT in' on every VTY line."
    ),
    references=(REF_CISCO_HARDEN, REF_CIS_IOS, REF_NSA_NIG),
)
def vty_no_access_class(cfg: DeviceConfig):
    bad, evidence = [], []
    for blk in _vty(cfg):
        ac = blk.access_class_in
        if ac is None:
            bad.append(blk.label)
            evidence.append(blk.stanza)
            continue
        acl = cfg.acls.get(ac[0])
        if acl and any(e.action == "permit" and not e.error and e.src.is_any for e in acl.entries):
            bad.append(f"{blk.label} (ACL {ac[0]} permits any source)")
            evidence.append(ac[1])
    if bad:
        yield Hit(obj="vty lines", detail="No effective source restriction on: " + "; ".join(bad) + ".",
                  evidence=evidence, affected=[b.split(" (")[0] for b in bad])


@rule(
    id="MGMT-003",
    title="Idle management sessions never time out",
    severity=Severity.MEDIUM,
    category="Management plane",
    risk=(
        "An exec session without an idle limit stays open indefinitely. A forgotten console or SSH session on an "
        "unattended terminal can be used by anyone who walks up to it."
    ),
    remediation="Set 'exec-timeout 5 0' (five minutes or less) under 'line con 0', 'line vty 0 15' and 'line aux 0'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
)
def exec_timeout_disabled(cfg: DeviceConfig):
    bad, evidence = [], []
    for blk in cfg.lines_of("con") + cfg.lines_of("vty") + cfg.lines_of("aux"):
        t = blk.exec_timeout_seconds
        if t and (t[0] == 0 or t[0] > 600):
            bad.append(f"{blk.label} ({'never' if t[0] == 0 else f'{t[0] // 60} min'})")
            evidence.append(t[1])
    if bad:
        yield Hit(obj="exec lines", detail="Idle timeout disabled or longer than 10 minutes on: " + "; ".join(bad) + ".",
                  evidence=evidence, affected=[b.split(" (")[0] for b in bad])


@rule(
    id="MGMT-004",
    title="No login banner",
    severity=Severity.LOW,
    category="Management plane",
    risk=(
        "Without a warning banner there is no notice that access is restricted and monitored, which weakens the basis "
        "for enforcing the acceptable-use policy. (Wording should come from your organisation's legal team.)"
    ),
    remediation="Configure 'banner login' (or 'banner motd') with an authorised-use notice that reveals no device details.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
)
def no_banner(cfg: DeviceConfig):
    if not ({"login", "motd"} & set(cfg.banners)):
        yield Hit(obj="global", detail="Neither 'banner login' nor 'banner motd' is configured.")


@rule(
    id="MGMT-005",
    title="HTTP management server is enabled",
    severity=Severity.HIGH,
    category="Management plane",
    risk=(
        "The built-in web server exposes an administration interface over unencrypted HTTP, so credentials and "
        "sessions can be sniffed, and the web UI has been affected by several remotely exploitable vulnerabilities."
    ),
    remediation="'no ip http server' (and 'no ip http secure-server' unless the HTTPS UI is actually needed and restricted).",
    references=(attack("T1040", "Network Sniffing"), REF_CIS_IOS, REF_CISCO_HARDEN),
)
def http_server_enabled(cfg: DeviceConfig):
    state, line = cfg.state("ip", "http", "server")
    if state:
        yield Hit(obj="global", detail="'ip http server' is enabled.", evidence=[line])


@rule(
    id="MGMT-006",
    title="AUX port is enabled",
    severity=Severity.MEDIUM,
    category="Management plane",
    risk=(
        "The AUX port is an out-of-band exec path that is easy to forget. If a modem or terminal server is attached it "
        "bypasses every network control, and an unauthenticated AUX line is an open door."
    ),
    remediation="'line aux 0' / 'no exec' / 'transport input none' / 'transport output none'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN),
    applies_to=("router",),
)
def aux_enabled(cfg: DeviceConfig):
    bad = [b for b in cfg.lines_of("aux") if not (b.exec_disabled or _transport_none(b))]
    if bad:
        yield Hit(obj="aux line", detail="The AUX line is not disabled ('no exec' / 'transport input none').",
                  evidence=[b.stanza for b in bad], affected=[b.label for b in bad])


@rule(
    id="MGMT-007",
    title="SNMP community string is a well-known default",
    severity=Severity.CRITICAL,
    category="Management plane",
    risk=(
        "'public' and 'private' are the first strings any scanner tries. Read access discloses configuration, routing "
        "and ARP tables; read-write access lets an attacker change the device over SNMP."
    ),
    remediation="Remove the community; use SNMPv3 with authentication and encryption ('snmp-server group ... v3 priv').",
    references=(attack("T1602.001", "Data from Configuration Repository: SNMP (MIB Dump)"), REF_CISCO_HARDEN, REF_CIS_IOS),
)
def snmp_default_community(cfg: DeviceConfig):
    bad = [l for l in cfg.top("snmp-server", "community") if len(l.words) >= 3 and l.words[2] in ("public", "private")]
    if bad:
        yield Hit(obj="snmp communities", detail=f"{len(bad)} community string(s) use a well-known default.",
                  evidence=bad, affected=[l.words[2] for l in bad])


@rule(
    id="MGMT-008",
    title="SNMP read-write community is configured",
    severity=Severity.HIGH,
    category="Management plane",
    risk=(
        "SNMPv1/v2c authenticates with a clear-text community string. A read-write community lets anyone who learns "
        "the string change configuration remotely."
    ),
    remediation="Remove 'RW' communities; if write access is unavoidable use SNMPv3 priv with a restricted view and ACL.",
    references=(attack("T1602.001", "Data from Configuration Repository: SNMP (MIB Dump)"), REF_CIS_IOS),
)
def snmp_rw(cfg: DeviceConfig):
    bad = [l for l in cfg.top("snmp-server", "community") if "rw" in l.words[3:]]
    if bad:
        yield Hit(obj="snmp communities", detail=f"{len(bad)} read-write community string(s) configured.",
                  evidence=bad, affected=[f"community #{i + 1}" for i in range(len(bad))])


@rule(
    id="MGMT-009",
    title="AAA is not enabled (local-only authentication)",
    severity=Severity.LOW,
    category="Management plane",
    risk=(
        "Without AAA there is no central account lifecycle, command authorisation or accounting: every device keeps its "
        "own accounts and nothing records who ran which command."
    ),
    remediation=(
        "Enable 'aaa new-model', authenticate against TACACS+/RADIUS with a local fallback "
        "('aaa authentication login default group tacacs+ local'), and add command accounting."
    ),
    references=(REF_CIS_IOS, REF_NSA_NIG),
)
def aaa_missing(cfg: DeviceConfig):
    if not cfg.state("aaa", "new-model")[0]:
        yield Hit(obj="global", detail="'aaa new-model' is not configured; only local accounts and line passwords exist.")


@rule(
    id="MGMT-010",
    title="SSH version 2 is not enforced",
    severity=Severity.MEDIUM,
    category="Management plane",
    risk=(
        "Unless 'ip ssh version 2' is set, IOS also accepts the legacy SSH-1 protocol, which has known cryptographic "
        "weaknesses. If SSH is not configured at all, administrators fall back to Telnet."
    ),
    remediation=(
        "Set a domain name, generate an RSA key of at least 2048 bits ('crypto key generate rsa modulus 2048') and enforce "
        "'ip ssh version 2'; add 'ip ssh time-out 60' and 'ip ssh authentication-retries 3'."
    ),
    references=(_REMOTE_ATTACK, REF_CIS_IOS, REF_CISCO_HARDEN),
)
def ssh_v2_not_enforced(cfg: DeviceConfig):
    # Whether an RSA key pair exists cannot be seen in a running-config - say so rather than guess.
    note = " (RSA key presence cannot be verified from a running-config)"
    version_lines = [l for l in cfg.top("ip", "ssh", "version")]
    if any(l.words[3:4] == ("2",) for l in version_lines):
        return
    if any(l.words[3:4] == ("1",) for l in version_lines):
        yield Hit(obj="global", detail="'ip ssh version 1' forces the legacy SSH-1 protocol.",
                  evidence=version_lines, severity=Severity.HIGH)
    else:
        yield Hit(obj="global", detail="'ip ssh version 2' is not configured" + note + ".")
