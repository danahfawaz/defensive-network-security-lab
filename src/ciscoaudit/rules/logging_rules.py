"""Logging and time (LOG-*)."""

from __future__ import annotations

import re

from ..model import Severity
from ..parser import DeviceConfig
from .base import REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG, Hit, rule

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@rule(
    id="LOG-001",
    title="No remote syslog server",
    severity=Severity.MEDIUM,
    category="Logging",
    risk=(
        "Without an off-box log destination the only evidence lives in volatile device memory: a reload, a full buffer or "
        "an attacker erases it, and nothing can be correlated or alerted on centrally."
    ),
    remediation="'logging host <syslog-server>' with 'logging trap informational' and a stable 'logging source-interface'.",
    references=(REF_CIS_IOS, REF_CISCO_HARDEN, REF_NSA_NIG),
)
def no_syslog_host(cfg: DeviceConfig):
    for line in cfg.top("logging"):
        if len(line.words) >= 3 and line.words[1] == "host":
            return
        if len(line.words) >= 2 and _IPV4.match(line.words[1]):
            return
    yield Hit(obj="global", detail="No 'logging host <address>' is configured.")


@rule(
    id="LOG-002",
    title="Log messages carry no date and time",
    severity=Severity.LOW,
    category="Logging",
    risk=(
        "Messages stamped only with uptime cannot be ordered against other systems' logs, so events cannot be correlated "
        "during an investigation."
    ),
    remediation="'service timestamps log datetime msec' and 'service timestamps debug datetime msec'.",
    references=(REF_CIS_IOS,),
)
def no_log_timestamps(cfg: DeviceConfig):
    on, off_line = False, None
    for line in cfg.top("service", "timestamps", "log"):
        on = "datetime" in line.words
    for line in cfg.top("no", "service", "timestamps", "log"):
        on, off_line = False, line
    if not on:
        yield Hit(obj="global", detail="'service timestamps log datetime' is not enabled.",
                  evidence=[off_line] if off_line else [])


@rule(
    id="LOG-003",
    title="No time source (NTP) is configured",
    severity=Severity.LOW,
    category="Logging",
    risk="Timestamps are only useful if every device agrees on the time; without NTP, clocks drift and logs cannot be correlated.",
    remediation="'ntp server <address>' (ideally authenticated with 'ntp authenticate' and 'ntp trusted-key').",
    references=(REF_CIS_IOS, REF_NSA_NIG),
)
def no_ntp(cfg: DeviceConfig):
    if not (cfg.top("ntp", "server") or cfg.top("ntp", "peer")):
        yield Hit(obj="global", detail="Neither 'ntp server' nor 'ntp peer' is configured.")
