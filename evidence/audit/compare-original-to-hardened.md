# Remediation comparison: original lab → hardened

## Open findings by severity

| Severity | original lab | hardened | Change | Accepted risk |
|---|---:|---:|---:|---:|
| Critical | 0 | 0 | +0 | 0 |
| High | 18 | 0 | -18 | 0 |
| Medium | 65 | 0 | -65 | 2 |
| Low | 67 | 0 | -67 | 3 |
| Info | 0 | 0 | +0 | 0 |
| **Total** | **150** | **0** | **-150** | **5** |

Of the 150 findings open before: **60 resolved**, **5 accepted as risk** (documented waiver), **0 still open**, and **85 belonged to devices that are not in the new audit scope** (decommissioned or out of scope - not counted as remediation). **0 new** finding(s) appeared.

## By rule

| Rule | Severity | Title | Devices original lab | Devices hardened | Accepted |
|---|---|---|---:|---:|---:|
| CRED-001 | high | No enable secret is configured | 7 | 0 | 0 |
| MGMT-001 | high | Telnet is accepted for remote management | 7 | 0 | 0 |
| RTE-001 | high | Routing updates are not authenticated | 4 | 0 | 0 |
| ACL-007 | medium | Router applies no ACL on any routed interface | 4 | 0 | 0 |
| AUTH-002 | medium | Console or AUX line has no authentication | 7 | 0 | 0 |
| L2-001 | medium | Switch ports negotiate trunking (DTP dynamic mode) | 3 | 0 | 0 |
| L2-005 | medium | Port security is not enabled on edge ports | 3 | 0 | 0 |
| L2-006 | medium | PortFast with BPDU Guard is missing on edge ports | 3 | 0 | 0 |
| L2-007 | medium | Unused ports are enabled | 3 | 0 | 0 |
| L2-008 | medium | Active ports use the default VLAN 1 | 3 | 0 | 0 |
| L2-011 | medium | DHCP snooping is not enabled | 3 | 0 | 1 |
| L2-012 | medium | Dynamic ARP Inspection is not enabled | 3 | 0 | 1 |
| LOG-001 | medium | No remote syslog server | 7 | 0 | 0 |
| MGMT-002 | medium | VTY access is not restricted to management hosts | 7 | 0 | 0 |
| MGMT-006 | medium | AUX port is enabled | 4 | 0 | 0 |
| MGMT-010 | medium | SSH version 2 is not enforced | 7 | 0 | 0 |
| RTE-002 | medium | RIP version 1 is in use | 4 | 0 | 0 |
| RTE-003 | medium | Routing protocol is active on every interface (no passive-interface) | 4 | 0 | 0 |
| AUTH-004 | low | Line requires a password but none is configured | 7 | 0 | 0 |
| CRED-005 | low | 'service password-encryption' is not enabled | 7 | 0 | 0 |
| INT-001 | low | Proxy ARP is enabled on routed interfaces | 4 | 0 | 0 |
| L2-010 | low | VTP is not in transparent or off mode | 3 | 0 | 0 |
| LOG-002 | low | Log messages carry no date and time | 7 | 0 | 0 |
| LOG-003 | low | No time source (NTP) is configured | 7 | 0 | 0 |
| MGMT-004 | low | No login banner | 7 | 0 | 0 |
| MGMT-009 | low | AAA is not enabled (local-only authentication) | 7 | 0 | 3 |
| SVC-001 | low | CDP is running | 7 | 0 | 0 |
| SVC-002 | low | IP source routing is enabled | 4 | 0 | 0 |
| SVC-004 | low | Device still uses the default hostname | 7 | 0 | 0 |

## By device

| original lab device | hardened device | Open before | Open after |
|---|---|---:|---:|
| Router1 | FW-EDGE | 21 | 0 |
| Router2 | (not in new scope) | 21 | - |
| Router3 | (not in new scope) | 21 | - |
| Router4 | (not in new scope) | 21 | - |
| Switch0 | SW-ACCESS | 22 | 0 |
| Switch1 | SW-DMZ | 22 | 0 |
| Switch2 | (not in new scope) | 22 | - |

Unmatched devices - only before: Router2, Router3, Router4, Switch2; only after: none.

## New findings (regressions)

None.

## Still open

None.

## Accepted risks

- medium · L2-011 · SW-DMZ · `global`: Both DMZ servers are statically addressed and the DMZ has no DHCP server, so snooping would have no bindings to build. The attack it prevents - a rogue DHCP server handing out a bad gateway or DNS server - needs DHCP clients, and there are none on this VLAN. Port security (sticky, maximum 1, violation shutdown) limits who can plug in. Revisit if a DHCP client is ever placed in the DMZ.
- medium · L2-012 · SW-DMZ · `global`: Dynamic ARP Inspection validates ARP against DHCP-snooping bindings; with static addressing there are none, so it would also need one ARP ACL entry per server. For two servers on port-secured ports that cost was judged greater than the benefit in this lab. Residual risk: a compromised DMZ server could ARP-spoof the other DMZ server or the firewall's DMZ interface and intercept DMZ traffic. FW-EDGE already prevents the DMZ from initiating connections to the internal network, which limits the impact.
- low · MGMT-009 · FW-EDGE · `global`: The lab has no TACACS+/RADIUS server, so authentication is local (AAA is future work, see docs/limitations.md). Compensating controls on the device: SSH version 2 only, 'login local' on every line, access to the VTY lines limited to the administrator workstation by VTY-ADMIN, a 5-minute exec timeout, and login throttling. The remaining weakness is that accounts are not centrally managed and commands are not accounted for.
- low · MGMT-009 · SW-ACCESS · `global`: Same as FW-EDGE: no AAA server in the lab. Compensating controls: SSH only, 'login local', VTY-ADMIN source restriction (administrator workstation 10.10.99.10), exec timeout.
- low · MGMT-009 · SW-DMZ · `global`: Same as FW-EDGE: no AAA server in the lab. Compensating controls: SSH only, 'login local', VTY-ADMIN source restriction, and FW-EDGE lets only the administrator workstation reach TCP/22 on this switch.
