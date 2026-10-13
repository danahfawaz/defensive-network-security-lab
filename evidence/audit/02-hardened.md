# Redesigned network, hardened configuration

*3 configuration file(s) · 52 rules · ciscoaudit 0.1.0*

## Summary

| Severity | Open | Accepted risk |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 0 | 2 |
| Low | 0 | 3 |
| Info | 0 | 0 |
| **Total** | **0** | **5** |

## Devices

| Device | Type | Model | Critical | High | Medium | Low | Info | Accepted risk |
|---|---|---|---:|---:|---:|---:|---:|---:|
| FW-EDGE | router | 1841 | 0 | 0 | 0 | 0 | 0 | 1 |
| SW-ACCESS | switch | 2960-24TT | 0 | 0 | 0 | 0 | 0 | 1 |
| SW-DMZ | switch | 2960-24TT | 0 | 0 | 0 | 0 | 0 | 3 |

## Findings

No open findings.

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
