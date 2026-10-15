# Audit of the running configurations exported from Packet Tracer

*3 configuration file(s) · 52 rules · ciscoaudit 0.1.0*

## Summary

| Severity | Open | Accepted risk |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 3 | 2 |
| Low | 9 | 3 |
| Info | 0 | 0 |
| **Total** | **12** | **5** |

## Devices

| Device | Type | Model | Critical | High | Medium | Low | Info | Accepted risk |
|---|---|---|---:|---:|---:|---:|---:|---:|
| FW-EDGE | router | - | 0 | 0 | 3 | 9 | 0 | 1 |
| SW-ACCESS | switch | - | 0 | 0 | 0 | 0 | 0 | 1 |
| SW-DMZ | switch | - | 0 | 0 | 0 | 0 | 0 | 3 |

## Findings

### MEDIUM · AUTH-002 · Console or AUX line has no authentication

*Access control · 1 device(s): FW-EDGE*

**Risk.** A line without 'login' gives an unauthenticated exec session to anyone with physical access, a serial console server or a modem on the AUX port. Out-of-band paths bypass every network-based control.

**Remediation.** Console: 'line con 0' / 'login local' / 'exec-timeout 5 0' / 'logging synchronous'. AUX: disable it ('line aux 0' / 'no exec' / 'transport input none') unless a modem is genuinely required.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark

- **FW-EDGE** - `console/aux lines`: No 'login' method is configured on: line aux 0.
  - `L262 line aux 0`

### MEDIUM · MGMT-003 · Idle management sessions never time out

*Management plane · 1 device(s): FW-EDGE*

**Risk.** An exec session without an idle limit stays open indefinitely. A forgotten console or SSH session on an unattended terminal can be used by anyone who walks up to it.

**Remediation.** Set 'exec-timeout 5 0' (five minutes or less) under 'line con 0', 'line vty 0 15' and 'line aux 0'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **FW-EDGE** - `exec lines`: Idle timeout disabled or longer than 10 minutes on: line aux 0 (never).
  - `L263 [line aux 0] exec-timeout 0 0`

### MEDIUM · MGMT-006 · AUX port is enabled

*Management plane · 1 device(s): FW-EDGE*

**Risk.** The AUX port is an out-of-band exec path that is easy to forget. If a modem or terminal server is attached it bypasses every network control, and an unauthenticated AUX line is an open door.

**Remediation.** 'line aux 0' / 'no exec' / 'transport input none' / 'transport output none'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **FW-EDGE** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L262 line aux 0`

### LOW · ACL-002 · Interface ACL does not end with a logged 'deny ip any any'

*Access lists · 1 device(s): FW-EDGE*

**Risk.** Packets dropped by the implicit deny at the end of an ACL are never logged, so scans and policy violations stay invisible to monitoring.

**Remediation.** End every interface ACL with 'deny ip any any log' (mind log rate limits on busy interfaces).

**References.** Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `ACL IN-DMZ`: ACL IN-DMZ has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L231 [ip access-list extended IN-DMZ] permit tcp host 172.16.50.20 eq domain any established`
- **FW-EDGE** - `ACL IN-GUEST`: ACL IN-GUEST has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L185 [ip access-list extended IN-GUEST] permit icmp 10.10.30.0 0.0.0.255 any echo`
- **FW-EDGE** - `ACL IN-MGMT`: ACL IN-MGMT has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L204 [ip access-list extended IN-MGMT] permit udp host 10.10.99.20 eq 123 host 172.16.50.2 eq 123`
- **FW-EDGE** - `ACL IN-OUTSIDE`: ACL IN-OUTSIDE has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L243 [ip access-list extended IN-OUTSIDE] permit icmp any host 203.0.113.2 unreachable`
- **FW-EDGE** - `ACL IN-SERVERS`: ACL IN-SERVERS has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L170 [ip access-list extended IN-SERVERS] permit icmp 10.10.20.0 0.0.0.255 host 10.10.20.1 echo`
- **FW-EDGE** - `ACL IN-USERS`: ACL IN-USERS has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L155 [ip access-list extended IN-USERS] permit icmp 10.10.10.0 0.0.0.255 any echo`

### LOW · ACL-005 · ACL is defined but never applied

*Access lists · 1 device(s): FW-EDGE*

**Risk.** A dead ACL gives operators the false impression that traffic is filtered; it also hides stale policy.

**Remediation.** Apply the ACL where it is meant to act, or delete it.

**References.** Cisco, Harden IOS Devices

- **FW-EDGE** - `ACLs`: No reference found for: sl_def_acl.
  - `L124 ip access-list extended sl_def_acl`

### LOW · ACL-006 · ACL entry is shadowed by an earlier entry

*Access lists · 1 device(s): FW-EDGE*

**Risk.** An entry that can never match is dead policy: the rule the author intended is not enforced and the ACL behaves differently from how it reads.

**Remediation.** Reorder so the specific entry comes first, or remove the redundant one.

**References.** Cisco, Harden IOS Devices

- **FW-EDGE** - `ACL sl_def_acl`: seq 40 is contradicted by seq 30.
  - `L128 [ip access-list extended sl_def_acl] permit tcp any any eq 22`
  - `L127 [ip access-list extended sl_def_acl] deny tcp any any eq 22`

### LOW · SVC-002 · IP source routing is enabled

*Services · 1 device(s): FW-EDGE*

**Risk.** Source-routed packets let the sender dictate the path they take, which can bypass routing-based controls and help spoofing or firewall evasion.

**Remediation.** 'no ip source-route'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **FW-EDGE** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).

## Accepted risks

These findings are acknowledged and waived; each keeps its written justification.

### L2-011 · DHCP snooping is not enabled

- **SW-DMZ** - `global` (medium): Both DMZ servers are statically addressed and the DMZ has no DHCP server, so snooping would have no bindings to build. The attack it prevents - a rogue DHCP server handing out a bad gateway or DNS server - needs DHCP clients, and there are none on this VLAN. Port security (sticky, maximum 1, violation shutdown) limits who can plug in. Revisit if a DHCP client is ever placed in the DMZ.

### L2-012 · Dynamic ARP Inspection is not enabled

- **SW-DMZ** - `global` (medium): Dynamic ARP Inspection validates ARP against DHCP-snooping bindings; with static addressing there are none, so it would also need one ARP ACL entry per server. For two servers on port-secured ports that cost was judged greater than the benefit in this lab. Residual risk: a compromised DMZ server could ARP-spoof the other DMZ server or the firewall's DMZ interface and intercept DMZ traffic. FW-EDGE already prevents the DMZ from initiating connections to the internal network, which limits the impact.

### MGMT-009 · AAA is not enabled (local-only authentication)

- **FW-EDGE** - `global` (low): The lab has no TACACS+/RADIUS server, so authentication is local (AAA is future work, see docs/limitations.md). Compensating controls on the device: SSH version 2 only, 'login local' on every line, access to the VTY lines limited to the administrator workstation by VTY-ADMIN, a 5-minute exec timeout, and login throttling. The remaining weakness is that accounts are not centrally managed and commands are not accounted for.
- **SW-ACCESS** - `global` (low): Same as FW-EDGE: no AAA server in the lab. Compensating controls: SSH only, 'login local', VTY-ADMIN source restriction (administrator workstation 10.10.99.10), exec timeout.
- **SW-DMZ** - `global` (low): Same as FW-EDGE: no AAA server in the lab. Compensating controls: SSH only, 'login local', VTY-ADMIN source restriction, and FW-EDGE lets only the administrator workstation reach TCP/22 on this switch.
