# Original university lab (Day 0)

*7 configuration file(s) · 52 rules · ciscoaudit 0.1.0*

## Summary

| Severity | Open | Accepted risk |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 18 | 0 |
| Medium | 65 | 0 |
| Low | 67 | 0 |
| Info | 0 | 0 |
| **Total** | **150** | **0** |

## Devices

| Device | Type | Model | Critical | High | Medium | Low | Info | Accepted risk |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Router1 (`Router`) | router | 1841 | 0 | 3 | 8 | 10 | 0 | 0 |
| Router2 (`Router`) | router | 1841 | 0 | 3 | 8 | 10 | 0 | 0 |
| Router3 (`Router`) | router | 1841 | 0 | 3 | 8 | 10 | 0 | 0 |
| Router4 (`Router`) | router | 1841 | 0 | 3 | 8 | 10 | 0 | 0 |
| Switch0 (`Switch`) | switch | 2960-24TT | 0 | 2 | 11 | 9 | 0 | 0 |
| Switch1 (`Switch`) | switch | 2960-24TT | 0 | 2 | 11 | 9 | 0 | 0 |
| Switch2 (`Switch`) | switch | 2960-24TT | 0 | 2 | 11 | 9 | 0 | 0 |

## Findings

### HIGH · CRED-001 · No enable secret is configured

*Credentials · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** With no enable secret, privileged EXEC is not password-protected at the console, so physical or console-server access means full control; remote users cannot elevate, which tempts administrators into giving every account privilege 15 instead.

**Remediation.** Set a strong, unique secret: 'enable secret <value>' (stored as a hash). Do not use 'enable password'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices; NSA, Cisco Password Types: Best Practices

- **Router1** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Router2** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Router3** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Router4** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Switch0** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Switch1** - `global`: Neither 'enable secret' nor 'enable password' is configured.
- **Switch2** - `global`: Neither 'enable secret' nor 'enable password' is configured.

### HIGH · MGMT-001 · Telnet is accepted for remote management

*Management plane · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Telnet sends credentials and every command in clear text. Anyone on the path - or an attacker who can sniff or ARP-spoof the segment - captures the administrator's password and can replay the session.

**Remediation.** Allow only SSH on the VTY lines: 'line vty 0 15' / 'transport input ssh'.

**References.** MITRE ATT&CK T1040 Network Sniffing; Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
  - `L87 line vty 0 4`
- **Router2** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
  - `L78 line vty 0 4`
- **Router3** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
  - `L78 line vty 0 4`
- **Router4** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
  - `L78 line vty 0 4`
- **Switch0** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet); line vty 5 15 (no 'transport input': IOS default accepts Telnet).
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`
- **Switch1** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet); line vty 5 15 (no 'transport input': IOS default accepts Telnet).
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`
- **Switch2** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet); line vty 5 15 (no 'transport input': IOS default accepts Telnet).
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`

### HIGH · RTE-001 · Routing updates are not authenticated

*Routing · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** Any host that can send packets to an interface running the protocol can inject routes - a default route or more-specific prefixes - and silently redirect, intercept or black-hole traffic.

**Remediation.** RIPv2: 'key chain' + 'ip rip authentication mode md5' + 'ip rip authentication key-chain'. OSPF: 'area <n> authentication message-digest' (or per-interface) with 'ip ospf message-digest-key'. Also make user-facing interfaces passive.

**References.** MITRE ATT&CK T1557 Adversary-in-the-Middle; Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `router rip`: 'router rip' sends and accepts unauthenticated updates on 3 interface(s). RIPv1 cannot authenticate at all.
  - `L64 router rip`
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
  - `L55 interface Ethernet0/1/0`
- **Router2** - `router rip`: 'router rip' sends and accepts unauthenticated updates on 2 interface(s). RIPv1 cannot authenticate at all.
  - `L59 router rip`
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router3** - `router rip`: 'router rip' sends and accepts unauthenticated updates on 2 interface(s). RIPv1 cannot authenticate at all.
  - `L59 router rip`
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router4** - `router rip`: 'router rip' sends and accepts unauthenticated updates on 2 interface(s). RIPv1 cannot authenticate at all.
  - `L59 router rip`
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`

### MEDIUM · ACL-007 · Router applies no ACL on any routed interface

*Access lists · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** With no traffic filtering every attached segment can reach every other: there are no security zones, and one compromised host can scan and attack the whole network.

**Remediation.** Define zone policy ACLs and apply them with 'ip access-group <name> in' on the interface closest to the source.

**References.** NSA, Network Infrastructure Security Guide; Cisco, Harden IOS Devices

- **Router1** - `interfaces`: 3 routed interfaces, none with 'ip access-group'.
- **Router2** - `interfaces`: 2 routed interfaces, none with 'ip access-group'.
- **Router3** - `interfaces`: 2 routed interfaces, none with 'ip access-group'.
- **Router4** - `interfaces`: 2 routed interfaces, none with 'ip access-group'.

### MEDIUM · AUTH-002 · Console or AUX line has no authentication

*Access control · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** A line without 'login' gives an unauthenticated exec session to anyone with physical access, a serial console server or a modem on the AUX port. Out-of-band paths bypass every network-based control.

**Remediation.** Console: 'line con 0' / 'login local' / 'exec-timeout 5 0' / 'logging synchronous'. AUX: disable it ('line aux 0' / 'no exec' / 'transport input none') unless a modem is genuinely required.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark

- **Router1** - `console/aux lines`: No 'login' method is configured on: line con 0, line aux 0.
  - `L83 line con 0`
  - `L85 line aux 0`
- **Router2** - `console/aux lines`: No 'login' method is configured on: line con 0, line aux 0.
  - `L74 line con 0`
  - `L76 line aux 0`
- **Router3** - `console/aux lines`: No 'login' method is configured on: line con 0, line aux 0.
  - `L74 line con 0`
  - `L76 line aux 0`
- **Router4** - `console/aux lines`: No 'login' method is configured on: line con 0, line aux 0.
  - `L74 line con 0`
  - `L76 line aux 0`
- **Switch0** - `console/aux lines`: No 'login' method is configured on: line con 0.
  - `L82 line con 0`
- **Switch1** - `console/aux lines`: No 'login' method is configured on: line con 0.
  - `L82 line con 0`
- **Switch2** - `console/aux lines`: No 'login' method is configured on: line con 0.
  - `L82 line con 0`

### MEDIUM · L2-001 · Switch ports negotiate trunking (DTP dynamic mode)

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** A port left in dynamic auto/desirable mode will turn itself into an 802.1Q trunk if the device on the other end asks it to. An attacker's host (or a rogue switch) then receives every VLAN the trunk carries.

**Remediation.** Set 'switchport mode access' on every end-user port and 'switchport mode trunk' + 'switchport nonegotiate' on uplinks.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Switch0** - `interfaces`: 26 enabled port(s) are in dynamic mode: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `interfaces`: 26 enabled port(s) are in dynamic mode: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `interfaces`: 26 enabled port(s) are in dynamic mode: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### MEDIUM · L2-005 · Port security is not enabled on edge ports

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** Without port security anyone can plug an unknown device into a live port, or flood the switch with spoofed source MACs until its CAM table overflows and it forwards traffic like a hub, exposing other users' frames.

**Remediation.** On access ports: 'switchport mode access', 'switchport port-security', 'switchport port-security maximum 2', 'switchport port-security mac-address sticky', 'switchport port-security violation restrict' (or shutdown).

**References.** MITRE ATT&CK T1200 Hardware Additions; MITRE ATT&CK T1557 Adversary-in-the-Middle; Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark

- **Switch0** - `interfaces`: 26 edge-capable port(s) lack port security: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `interfaces`: 26 edge-capable port(s) lack port security: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `interfaces`: 26 edge-capable port(s) lack port security: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### MEDIUM · L2-006 · PortFast with BPDU Guard is missing on edge ports

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** A switch (or a host running a bridging tool) plugged into an edge port can send BPDUs, win the root-bridge election and pull traffic through itself, or trigger repeated reconvergence and an outage.

**Remediation.** 'spanning-tree portfast' + 'spanning-tree bpduguard enable' per port, or 'spanning-tree portfast default' + 'spanning-tree portfast bpduguard default' globally.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Switch0** - `interfaces`: 26 edge-capable port(s) lack PortFast + BPDU Guard: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `interfaces`: 26 edge-capable port(s) lack PortFast + BPDU Guard: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `interfaces`: 26 edge-capable port(s) lack PortFast + BPDU Guard: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### MEDIUM · L2-007 · Unused ports are enabled

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** A live, unconfigured port is an open door for anyone with physical access: plug in and you are on the network (usually in VLAN 1).

**Remediation.** 'shutdown' every unused port and park it in an unused VLAN ('switchport access vlan 999').

**References.** MITRE ATT&CK T1200 Hardware Additions; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Switch0** - `interfaces`: 26 port(s) are up with default configuration: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `interfaces`: 26 port(s) are up with default configuration: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `interfaces`: 26 port(s) are up with default configuration: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### MEDIUM · L2-008 · Active ports use the default VLAN 1

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** VLAN 1 cannot be deleted and carries control-plane protocols (CDP, VTP, DTP, STP). Placing users there removes any segmentation and exposes those protocols to them.

**Remediation.** Assign end-user ports to purpose-built VLANs ('switchport access vlan 10') and keep VLAN 1 empty.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Switch0** - `interfaces`: 26 active port(s) are in VLAN 1: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `interfaces`: 26 active port(s) are in VLAN 1: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `interfaces`: 26 active port(s) are in VLAN 1: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### MEDIUM · L2-011 · DHCP snooping is not enabled

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** Any port can answer DHCP requests. A rogue DHCP server hands clients its own default gateway or DNS server (a man-in-the-middle position) or exhausts the address pool (denial of service), and the switch has no binding table that ties each IP address to a port - which Dynamic ARP Inspection also needs.

**Remediation.** 'ip dhcp snooping' and 'ip dhcp snooping vlan <ids>'; mark only the uplink toward the real DHCP server with 'ip dhcp snooping trust'; rate-limit client ports with 'ip dhcp snooping limit rate 15'.

**References.** MITRE ATT&CK T1557 Adversary-in-the-Middle; Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide

- **Switch0** - `global`: 'ip dhcp snooping' is not enabled.
- **Switch1** - `global`: 'ip dhcp snooping' is not enabled.
- **Switch2** - `global`: 'ip dhcp snooping' is not enabled.

### MEDIUM · L2-012 · Dynamic ARP Inspection is not enabled

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** Without Dynamic ARP Inspection any host can poison its neighbours' ARP caches (ARP spoofing) and sit between them and their gateway, reading or altering traffic that never leaves the VLAN, which no router ACL can see.

**Remediation.** 'ip arp inspection vlan <ids>' on VLANs whose hosts get their addresses through DHCP snooping; trust only uplinks ('ip arp inspection trust'); use ARP ACLs for statically addressed hosts.

**References.** MITRE ATT&CK T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning; Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide

- **Switch0** - `global`: 'ip arp inspection vlan' is not configured.
- **Switch1** - `global`: 'ip arp inspection vlan' is not configured.
- **Switch2** - `global`: 'ip arp inspection vlan' is not configured.

### MEDIUM · LOG-001 · No remote syslog server

*Logging · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Without an off-box log destination the only evidence lives in volatile device memory: a reload, a full buffer or an attacker erases it, and nothing can be correlated or alerted on centrally.

**Remediation.** 'logging host <syslog-server>' with 'logging trap informational' and a stable 'logging source-interface'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide

- **Router1** - `global`: No 'logging host <address>' is configured.
- **Router2** - `global`: No 'logging host <address>' is configured.
- **Router3** - `global`: No 'logging host <address>' is configured.
- **Router4** - `global`: No 'logging host <address>' is configured.
- **Switch0** - `global`: No 'logging host <address>' is configured.
- **Switch1** - `global`: No 'logging host <address>' is configured.
- **Switch2** - `global`: No 'logging host <address>' is configured.

### MEDIUM · MGMT-002 · VTY access is not restricted to management hosts

*Management plane · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Without an 'access-class', every host that can route to any interface of the device may attempt to log in or exploit the management services. A management ACL shrinks that audience to a few administrator addresses.

**Remediation.** Define 'ip access-list standard VTY-MGMT' permitting only the admin host(s) and a final 'deny any log', then apply 'access-class VTY-MGMT in' on every VTY line.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `vty lines`: No effective source restriction on: line vty 0 4.
  - `L87 line vty 0 4`
- **Router2** - `vty lines`: No effective source restriction on: line vty 0 4.
  - `L78 line vty 0 4`
- **Router3** - `vty lines`: No effective source restriction on: line vty 0 4.
  - `L78 line vty 0 4`
- **Router4** - `vty lines`: No effective source restriction on: line vty 0 4.
  - `L78 line vty 0 4`
- **Switch0** - `vty lines`: No effective source restriction on: line vty 0 4; line vty 5 15.
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`
- **Switch1** - `vty lines`: No effective source restriction on: line vty 0 4; line vty 5 15.
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`
- **Switch2** - `vty lines`: No effective source restriction on: line vty 0 4; line vty 5 15.
  - `L84 line vty 0 4`
  - `L86 line vty 5 15`

### MEDIUM · MGMT-006 · AUX port is enabled

*Management plane · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** The AUX port is an out-of-band exec path that is easy to forget. If a modem or terminal server is attached it bypasses every network control, and an unauthenticated AUX line is an open door.

**Remediation.** 'line aux 0' / 'no exec' / 'transport input none' / 'transport output none'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L85 line aux 0`
- **Router2** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L76 line aux 0`
- **Router3** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L76 line aux 0`
- **Router4** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L76 line aux 0`

### MEDIUM · MGMT-010 · SSH version 2 is not enforced

*Management plane · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Unless 'ip ssh version 2' is set, IOS also accepts the legacy SSH-1 protocol, which has known cryptographic weaknesses. If SSH is not configured at all, administrators fall back to Telnet.

**Remediation.** Set a domain name, generate an RSA key of at least 2048 bits ('crypto key generate rsa modulus 2048') and enforce 'ip ssh version 2'; add 'ip ssh time-out 60' and 'ip ssh authentication-retries 3'.

**References.** MITRE ATT&CK T1021.004 Remote Services: SSH; CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Router2** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Router3** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Router4** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Switch0** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Switch1** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **Switch2** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).

### MEDIUM · RTE-002 · RIP version 1 is in use

*Routing · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** RIPv1 is classful (updates carry no subnet masks, so VLSM designs cannot be expressed), broadcasts its updates and has no authentication, so any host on the segment can spoof a neighbour.

**Remediation.** 'router rip' / 'version 2' / 'no auto-summary' with authentication, or migrate to OSPF.

**References.** Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide

- **Router1** - `router rip`: No 'version 2' under 'router rip': the process sends RIPv1 (classful) updates.
  - `L64 router rip`
- **Router2** - `router rip`: No 'version 2' under 'router rip': the process sends RIPv1 (classful) updates.
  - `L59 router rip`
- **Router3** - `router rip`: No 'version 2' under 'router rip': the process sends RIPv1 (classful) updates.
  - `L59 router rip`
- **Router4** - `router rip`: No 'version 2' under 'router rip': the process sends RIPv1 (classful) updates.
  - `L59 router rip`

### MEDIUM · RTE-003 · Routing protocol is active on every interface (no passive-interface)

*Routing · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** Without passive interfaces the router sends and accepts routing updates on user-facing segments too, so a host there can learn the topology, form adjacencies or inject routes.

**Remediation.** Use 'passive-interface default' under the routing process, then 'no passive-interface <link>' only on interfaces that face routers.

**References.** Cisco, Harden IOS Devices; NSA, Network Infrastructure Security Guide; CIS Cisco IOS Benchmark

- **Router1** - `router rip`: 'router rip' has no 'passive-interface' statement; it is active on 3 interface(s).
  - `L64 router rip`
- **Router2** - `router rip`: 'router rip' has no 'passive-interface' statement; it is active on 2 interface(s).
  - `L59 router rip`
- **Router3** - `router rip`: 'router rip' has no 'passive-interface' statement; it is active on 2 interface(s).
  - `L59 router rip`
- **Router4** - `router rip`: 'router rip' has no 'passive-interface' statement; it is active on 2 interface(s).
  - `L59 router rip`

### LOW · AUTH-004 · Line requires a password but none is configured

*Access control · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** 'login' without a line password makes IOS reject every attempt ('Password required, but none set'). The line is unusable, and the usual quick fix - adding one shared password - is weaker than per-user authentication.

**Remediation.** Switch the line to 'login local' and create per-user accounts with 'username ... secret ...'.

**References.** Cisco, Harden IOS Devices

- **Router1** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4.
  - `L88 [line vty 0 4] login`
- **Router2** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4.
  - `L79 [line vty 0 4] login`
- **Router3** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4.
  - `L79 [line vty 0 4] login`
- **Router4** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4.
  - `L79 [line vty 0 4] login`
- **Switch0** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4, line vty 5 15.
  - `L85 [line vty 0 4] login`
  - `L87 [line vty 5 15] login`
- **Switch1** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4, line vty 5 15.
  - `L85 [line vty 0 4] login`
  - `L87 [line vty 5 15] login`
- **Switch2** - `lines without credentials`: 'login' is set but no 'password' exists on: line vty 0 4, line vty 5 15.
  - `L85 [line vty 0 4] login`
  - `L87 [line vty 5 15] login`

### LOW · CRED-005 · 'service password-encryption' is not enabled

*Credentials · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Line and username passwords that are not otherwise hashed appear in clear text in 'show running-config'. The service adds type 7 obfuscation, which is weak, but it stops casual disclosure by shoulder-surfing or a pasted screenshot.

**Remediation.** 'service password-encryption', and store credentials with 'secret' so they are hashed in the first place.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Router2** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Router3** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Router4** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Switch0** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Switch1** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`
- **Switch2** - `global`: 'service password-encryption' is off (explicitly disabled); no clear-text credentials are present right now.
  - `L11 no service password-encryption`

### LOW · INT-001 · Proxy ARP is enabled on routed interfaces

*Interfaces · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** With proxy ARP the router answers ARP requests on behalf of other subnets. This masks misconfigured masks, lets hosts without a gateway reach other segments through the router, and widens the effect of ARP spoofing.

**Remediation.** 'no ip proxy-arp' on every routed interface or subinterface.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `interfaces`: Proxy ARP is active (default) on 3 routed interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
  - `L55 interface Ethernet0/1/0`
- **Router2** - `interfaces`: Proxy ARP is active (default) on 2 routed interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router3** - `interfaces`: Proxy ARP is active (default) on 2 routed interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router4** - `interfaces`: Proxy ARP is active (default) on 2 routed interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`

### LOW · L2-010 · VTP is not in transparent or off mode

*Layer 2 · 3 device(s): Switch0, Switch1, Switch2*

**Risk.** In VTP server or client mode, a switch advertising a higher revision number overwrites the VLAN database of every switch in the domain - by accident or on purpose - deleting VLANs and causing an outage.

**Remediation.** 'vtp mode transparent' (or 'vtp mode off' where supported) and manage VLANs per switch.

**References.** Cisco, Harden IOS Devices; CIS Cisco IOS Benchmark

- **Switch0** - `global`: No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).
- **Switch1** - `global`: No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).
- **Switch2** - `global`: No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).

### LOW · LOG-002 · Log messages carry no date and time

*Logging · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Messages stamped only with uptime cannot be ordered against other systems' logs, so events cannot be correlated during an investigation.

**Remediation.** 'service timestamps log datetime msec' and 'service timestamps debug datetime msec'.

**References.** CIS Cisco IOS Benchmark

- **Router1** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Router2** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Router3** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Router4** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Switch0** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Switch1** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **Switch2** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`

### LOW · LOG-003 · No time source (NTP) is configured

*Logging · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Timestamps are only useful if every device agrees on the time; without NTP, clocks drift and logs cannot be correlated.

**Remediation.** 'ntp server <address>' (ideally authenticated with 'ntp authenticate' and 'ntp trusted-key').

**References.** CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Router2** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Router3** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Router4** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Switch0** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Switch1** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **Switch2** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.

### LOW · MGMT-004 · No login banner

*Management plane · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Without a warning banner there is no notice that access is restricted and monitored, which weakens the basis for enforcing the acceptable-use policy. (Wording should come from your organisation's legal team.)

**Remediation.** Configure 'banner login' (or 'banner motd') with an authorised-use notice that reveals no device details.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Router2** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Router3** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Router4** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Switch0** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Switch1** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **Switch2** - `global`: Neither 'banner login' nor 'banner motd' is configured.

### LOW · MGMT-009 · AAA is not enabled (local-only authentication)

*Management plane · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Without AAA there is no central account lifecycle, command authorisation or accounting: every device keeps its own accounts and nothing records who ran which command.

**Remediation.** Enable 'aaa new-model', authenticate against TACACS+/RADIUS with a local fallback ('aaa authentication login default group tacacs+ local'), and add command accounting.

**References.** CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Router2** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Router3** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Router4** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Switch0** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Switch1** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **Switch2** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.

### LOW · SVC-001 · CDP is running

*Services · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** CDP advertises the model, IOS version, interface names and management addresses to anything on the link, in clear text and without authentication. Attackers use it for reconnaissance, and CDP parsers have been affected by remotely exploitable bugs. The exposure matters most on ports that face users.

**Remediation.** 'no cdp run' globally, or 'no cdp enable' on every interface that does not face a trusted neighbour.

**References.** MITRE ATT&CK T1016 System Network Configuration Discovery; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **Router1** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 3 up interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
  - `L55 interface Ethernet0/1/0`
- **Router2** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 2 up interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router3** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 2 up interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Router4** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 2 up interface(s).
  - `L45 interface FastEthernet0/0`
  - `L50 interface FastEthernet0/1`
- **Switch0** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 26 up interface(s).
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch1** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 26 up interface(s).
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`
- **Switch2** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 26 up interface(s).
  - `L23 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L27 interface FastEthernet0/3`
  - `L29 interface FastEthernet0/4`
  - `L31 interface FastEthernet0/5`
  - `L33 interface FastEthernet0/6`
  - `L35 interface FastEthernet0/7`
  - `L37 interface FastEthernet0/8`

### LOW · SVC-002 · IP source routing is enabled

*Services · 4 device(s): Router1, Router2, Router3, Router4*

**Risk.** Source-routed packets let the sender dictate the path they take, which can bypass routing-based controls and help spoofing or firewall evasion.

**Remediation.** 'no ip source-route'.

**References.** CIS Cisco IOS Benchmark; Cisco, Harden IOS Devices

- **Router1** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).
- **Router2** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).
- **Router3** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).
- **Router4** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).

### LOW · SVC-004 · Device still uses the default hostname

*Services · 7 device(s): Router1, Router2, Router3, Router4, Switch0, Switch1, Switch2*

**Risk.** Devices called 'Router' or 'Switch' cannot be told apart in syslog, SNMP traps, SSH host-key warnings or change records, which makes incident response and change control error-prone.

**Remediation.** Give every device a unique, role-based name: 'hostname HQ-EDGE'.

**References.** CIS Cisco IOS Benchmark

- **Router1** - `global`: Hostname is 'Router'.
  - `L13 hostname Router`
- **Router2** - `global`: Hostname is 'Router'.
  - `L13 hostname Router`
- **Router3** - `global`: Hostname is 'Router'.
  - `L13 hostname Router`
- **Router4** - `global`: Hostname is 'Router'.
  - `L13 hostname Router`
- **Switch0** - `global`: Hostname is 'Switch'.
  - `L13 hostname Switch`
- **Switch1** - `global`: Hostname is 'Switch'.
  - `L13 hostname Switch`
- **Switch2** - `global`: Hostname is 'Switch'.
  - `L13 hostname Switch`
