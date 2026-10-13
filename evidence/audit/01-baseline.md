# Redesigned network, baseline configuration

*3 configuration file(s) · 52 rules · ciscoaudit 0.1.0*

## Summary

| Severity | Open | Accepted risk |
|---|---:|---:|
| Critical | 3 | 0 |
| High | 7 | 0 |
| Medium | 33 | 0 |
| Low | 22 | 0 |
| Info | 0 | 0 |
| **Total** | **65** | **0** |

## Devices

| Device | Type | Model | Critical | High | Medium | Low | Info | Accepted risk |
|---|---|---|---:|---:|---:|---:|---:|---:|
| FW-EDGE | router | 1841 | 1 | 3 | 8 | 8 | 0 | 0 |
| SW-ACCESS | switch | 2960-24TT | 1 | 2 | 13 | 8 | 0 | 0 |
| SW-DMZ | switch | 2960-24TT | 1 | 2 | 12 | 6 | 0 | 0 |

## Findings

### CRITICAL · CRED-004 · A well-known or default password is in use

*Credentials · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Passwords such as 'cisco' or 'admin' are the first guesses of every attacker and scanner. The check works even on hashed values because the salt is stored with the hash.

**Remediation.** Replace the credential with a unique passphrase (14+ characters) and rotate anything derived from it.

**References.** MITRE ATT&CK T1078.001 Valid Accounts: Default Accounts; MITRE ATT&CK T1110.001 Brute Force: Password Guessing; NSA, Cisco Password Types: Best Practices

- **FW-EDGE** - `credentials`: Matches the built-in list of well-known passwords (the value is deliberately not shown): enable password, line con 0, line vty 0 4.
  - `L18 enable password <redacted>`
  - `L87 [line con 0] password <redacted>`
  - `L93 [line vty 0 4] password <redacted>`
- **SW-ACCESS** - `credentials`: Matches the built-in list of well-known passwords (the value is deliberately not shown): enable password, line con 0, line vty 0 4, line vty 5 15.
  - `L15 enable password <redacted>`
  - `L70 [line con 0] password <redacted>`
  - `L74 [line vty 0 4] password <redacted>`
  - `L78 [line vty 5 15] password <redacted>`
- **SW-DMZ** - `credentials`: Matches the built-in list of well-known passwords (the value is deliberately not shown): enable password, line con 0, line vty 0 4, line vty 5 15.
  - `L13 enable password <redacted>`
  - `L47 [line con 0] password <redacted>`
  - `L51 [line vty 0 4] password <redacted>`
  - `L55 [line vty 5 15] password <redacted>`

### HIGH · CRED-002 · Credentials are stored in clear text or in reversible form

*Credentials · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Type 0 is plain text and type 7 is a reversible Vigenere-style encoding that public tools undo instantly. Anyone who can read a configuration backup, a TFTP capture or a screen share recovers the password.

**Remediation.** Replace 'enable password' with 'enable secret'; use 'username <name> secret <value>' instead of 'password'; prefer 'login local' to line passwords. Enable 'service password-encryption' only as a second line of defence.

**References.** MITRE ATT&CK T1552.001 Unsecured Credentials: Credentials In Files; NSA, Cisco Password Types: Best Practices; CIS Cisco IOS Benchmark

- **FW-EDGE** - `credentials`: 3 credential(s) are recoverable from the configuration (3 in clear text, 0 type 7): enable password, line con 0, line vty 0 4.
  - `L18 enable password <redacted>`
  - `L87 [line con 0] password <redacted>`
  - `L93 [line vty 0 4] password <redacted>`
- **SW-ACCESS** - `credentials`: 4 credential(s) are recoverable from the configuration (4 in clear text, 0 type 7): enable password, line con 0, line vty 0 4, line vty 5 15.
  - `L15 enable password <redacted>`
  - `L70 [line con 0] password <redacted>`
  - `L74 [line vty 0 4] password <redacted>`
  - `L78 [line vty 5 15] password <redacted>`
- **SW-DMZ** - `credentials`: 4 credential(s) are recoverable from the configuration (4 in clear text, 0 type 7): enable password, line con 0, line vty 0 4, line vty 5 15.
  - `L13 enable password <redacted>`
  - `L47 [line con 0] password <redacted>`
  - `L51 [line vty 0 4] password <redacted>`
  - `L55 [line vty 5 15] password <redacted>`

### HIGH · MGMT-001 · Telnet is accepted for remote management

*Management plane · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Telnet sends credentials and every command in clear text. Anyone on the path - or an attacker who can sniff or ARP-spoof the segment - captures the administrator's password and can replay the session.

**Remediation.** Allow only SSH on the VTY lines: 'line vty 0 15' / 'transport input ssh'.

**References.** MITRE ATT&CK T1040 Network Sniffing; Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
  - `L92 line vty 0 4`
- **SW-ACCESS** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet); line vty 5 15 (no 'transport input': IOS default accepts Telnet).
  - `L73 line vty 0 4`
  - `L77 line vty 5 15`
- **SW-DMZ** - `vty lines`: Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet); line vty 5 15 (no 'transport input': IOS default accepts Telnet).
  - `L50 line vty 0 4`
  - `L54 line vty 5 15`

### HIGH · MGMT-005 · HTTP management server is enabled

*Management plane · 1 device(s): FW-EDGE*

**Risk.** The built-in web server exposes an administration interface over unencrypted HTTP, so credentials and sessions can be sniffed, and the web UI has been affected by several remotely exploitable vulnerabilities.

**Remediation.** 'no ip http server' (and 'no ip http secure-server' unless the HTTPS UI is actually needed and restricted).

**References.** MITRE ATT&CK T1040 Network Sniffing; CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `global`: 'ip http server' is enabled.
  - `L79 ip http server`

### MEDIUM · ACL-001 · ACL contains a 'permit any any' entry

*Access lists · 1 device(s): FW-EDGE*

**Risk.** An unrestricted permit turns an ACL into a blocklist: everything not explicitly denied above it is allowed, including new services, spoofed sources and lateral movement. As the first matching entry it disables the ACL.

**Remediation.** Replace it with the specific flows that are needed and finish with an explicit 'deny ip any any log'.

**References.** Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `ACL 101`: 'access-list 101 permit ip any any' permits all traffic after some deny entries (blocklist style).
  - `L84 access-list 101 permit ip any any`

### MEDIUM · AUTH-002 · Console or AUX line has no authentication

*Access control · 1 device(s): FW-EDGE*

**Risk.** A line without 'login' gives an unauthenticated exec session to anyone with physical access, a serial console server or a modem on the AUX port. Out-of-band paths bypass every network-based control.

**Remediation.** Console: 'line con 0' / 'login local' / 'exec-timeout 5 0' / 'logging synchronous'. AUX: disable it ('line aux 0' / 'no exec' / 'transport input none') unless a modem is genuinely required.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark

- **FW-EDGE** - `console/aux lines`: No 'login' method is configured on: line aux 0.
  - `L90 line aux 0`

### MEDIUM · AUTH-003 · VTY lines use one shared line password instead of per-user accounts

*Access control · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** A single password shared by every administrator leaves no per-person audit trail, cannot be revoked for one person without changing it for all, and is easy to guess, share or leak.

**Remediation.** Use 'login local' with one 'username ... secret ...' per administrator (or AAA with TACACS+/RADIUS).

**References.** Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `vty lines`: A line password is used for authentication on: line vty 0 4.
  - `L94 [line vty 0 4] login`
  - `L93 [line vty 0 4] password <redacted>`
- **SW-ACCESS** - `vty lines`: A line password is used for authentication on: line vty 0 4, line vty 5 15.
  - `L75 [line vty 0 4] login`
  - `L79 [line vty 5 15] login`
  - `L74 [line vty 0 4] password <redacted>`
  - `L78 [line vty 5 15] password <redacted>`
- **SW-DMZ** - `vty lines`: A line password is used for authentication on: line vty 0 4, line vty 5 15.
  - `L52 [line vty 0 4] login`
  - `L56 [line vty 5 15] login`
  - `L51 [line vty 0 4] password <redacted>`
  - `L55 [line vty 5 15] password <redacted>`

### MEDIUM · CRED-005 · 'service password-encryption' is not enabled

*Credentials · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Line and username passwords that are not otherwise hashed appear in clear text in 'show running-config'. The service adds type 7 obfuscation, which is weak, but it stops casual disclosure by shoulder-surfing or a pasted screenshot.

**Remediation.** 'service password-encryption', and store credentials with 'secret' so they are hashed in the first place.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `global`: 'service password-encryption' is off (explicitly disabled) and 3 credential(s) are stored in clear text.
  - `L14 no service password-encryption`
- **SW-ACCESS** - `global`: 'service password-encryption' is off (explicitly disabled) and 4 credential(s) are stored in clear text.
  - `L11 no service password-encryption`
- **SW-DMZ** - `global`: 'service password-encryption' is off (explicitly disabled) and 4 credential(s) are stored in clear text.
  - `L9 no service password-encryption`

### MEDIUM · L2-001 · Switch ports negotiate trunking (DTP dynamic mode)

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** A port left in dynamic auto/desirable mode will turn itself into an 802.1Q trunk if the device on the other end asks it to. An attacker's host (or a rogue switch) then receives every VLAN the trunk carries.

**Remediation.** Set 'switchport mode access' on every end-user port and 'switchport mode trunk' + 'switchport nonegotiate' on uplinks.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `interfaces`: 19 enabled port(s) are in dynamic mode: FastEthernet0/8, FastEthernet0/9, FastEthernet0/10, FastEthernet0/11, FastEthernet0/12 and 14 more.
  - `L56 interface range FastEthernet0/8 - 24`
  - `L58 interface range GigabitEthernet0/1 - 2`
- **SW-DMZ** - `interfaces`: 23 enabled port(s) are in dynamic mode: FastEthernet0/4, FastEthernet0/5, FastEthernet0/6, FastEthernet0/7, FastEthernet0/8 and 18 more.
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### MEDIUM · L2-003 · Trunk native VLAN is the default VLAN 1

*Layer 2 · 1 device(s): SW-ACCESS*

**Risk.** Native-VLAN frames cross a trunk untagged. A host in the native VLAN can double-tag frames so that the first switch strips the outer tag and the second delivers the packet into another VLAN (VLAN hopping).

**Remediation.** Use an unused VLAN as native VLAN on every trunk: 'switchport trunk native vlan 999' (no ports or SVI in it).

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `interfaces`: 1 trunk(s) use native VLAN 1: FastEthernet0/3.
  - `L37 interface FastEthernet0/3`

### MEDIUM · L2-005 · Port security is not enabled on edge ports

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** Without port security anyone can plug an unknown device into a live port, or flood the switch with spoofed source MACs until its CAM table overflows and it forwards traffic like a hub, exposing other users' frames.

**Remediation.** On access ports: 'switchport mode access', 'switchport port-security', 'switchport port-security maximum 2', 'switchport port-security mac-address sticky', 'switchport port-security violation restrict' (or shutdown).

**References.** MITRE ATT&CK T1200 Hardware Additions; MITRE ATT&CK T1557 Adversary-in-the-Middle; Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark

- **SW-ACCESS** - `interfaces`: 25 edge-capable port(s) lack port security: FastEthernet0/1, FastEthernet0/2, FastEthernet0/4, FastEthernet0/5, FastEthernet0/6 and 20 more.
  - `L29 interface FastEthernet0/1`
  - `L33 interface FastEthernet0/2`
  - `L40 interface FastEthernet0/4`
  - `L44 interface FastEthernet0/5`
  - `L48 interface FastEthernet0/6`
  - `L52 interface FastEthernet0/7`
  - `L56 interface range FastEthernet0/8 - 24`
  - `L58 interface range GigabitEthernet0/1 - 2`
- **SW-DMZ** - `interfaces`: 26 edge-capable port(s) lack port security: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L21 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L29 interface FastEthernet0/3`
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### MEDIUM · L2-006 · PortFast with BPDU Guard is missing on edge ports

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** A switch (or a host running a bridging tool) plugged into an edge port can send BPDUs, win the root-bridge election and pull traffic through itself, or trigger repeated reconvergence and an outage.

**Remediation.** 'spanning-tree portfast' + 'spanning-tree bpduguard enable' per port, or 'spanning-tree portfast default' + 'spanning-tree portfast bpduguard default' globally.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `interfaces`: 25 edge-capable port(s) lack PortFast + BPDU Guard: FastEthernet0/1, FastEthernet0/2, FastEthernet0/4, FastEthernet0/5, FastEthernet0/6 and 20 more.
  - `L29 interface FastEthernet0/1`
  - `L33 interface FastEthernet0/2`
  - `L40 interface FastEthernet0/4`
  - `L44 interface FastEthernet0/5`
  - `L48 interface FastEthernet0/6`
  - `L52 interface FastEthernet0/7`
  - `L56 interface range FastEthernet0/8 - 24`
  - `L58 interface range GigabitEthernet0/1 - 2`
- **SW-DMZ** - `interfaces`: 26 edge-capable port(s) lack PortFast + BPDU Guard: FastEthernet0/1, FastEthernet0/2, FastEthernet0/3, FastEthernet0/4, FastEthernet0/5 and 21 more.
  - `L21 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L29 interface FastEthernet0/3`
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### MEDIUM · L2-007 · Unused ports are enabled

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** A live, unconfigured port is an open door for anyone with physical access: plug in and you are on the network (usually in VLAN 1).

**Remediation.** 'shutdown' every unused port and park it in an unused VLAN ('switchport access vlan 999').

**References.** MITRE ATT&CK T1200 Hardware Additions; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `interfaces`: 19 port(s) are up with default configuration: FastEthernet0/8, FastEthernet0/9, FastEthernet0/10, FastEthernet0/11, FastEthernet0/12 and 14 more.
  - `L56 interface range FastEthernet0/8 - 24`
  - `L58 interface range GigabitEthernet0/1 - 2`
- **SW-DMZ** - `interfaces`: 23 port(s) are up with default configuration: FastEthernet0/4, FastEthernet0/5, FastEthernet0/6, FastEthernet0/7, FastEthernet0/8 and 18 more.
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### MEDIUM · L2-008 · Active ports use the default VLAN 1

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** VLAN 1 cannot be deleted and carries control-plane protocols (CDP, VTP, DTP, STP). Placing users there removes any segmentation and exposes those protocols to them.

**Remediation.** Assign end-user ports to purpose-built VLANs ('switchport access vlan 10') and keep VLAN 1 empty.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `interfaces`: 19 active port(s) are in VLAN 1: FastEthernet0/8, FastEthernet0/9, FastEthernet0/10, FastEthernet0/11, FastEthernet0/12 and 14 more.
  - `L56 interface range FastEthernet0/8 - 24`
  - `L58 interface range GigabitEthernet0/1 - 2`
- **SW-DMZ** - `interfaces`: 23 active port(s) are in VLAN 1: FastEthernet0/4, FastEthernet0/5, FastEthernet0/6, FastEthernet0/7, FastEthernet0/8 and 18 more.
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### MEDIUM · L2-011 · DHCP snooping is not enabled

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** Any port can answer DHCP requests. A rogue DHCP server hands clients its own default gateway or DNS server (a man-in-the-middle position) or exhausts the address pool (denial of service), and the switch has no binding table that ties each IP address to a port - which Dynamic ARP Inspection also needs.

**Remediation.** 'ip dhcp snooping' and 'ip dhcp snooping vlan <ids>'; mark only the uplink toward the real DHCP server with 'ip dhcp snooping trust'; rate-limit client ports with 'ip dhcp snooping limit rate 15'.

**References.** MITRE ATT&CK T1557 Adversary-in-the-Middle; Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `global`: 'ip dhcp snooping' is not enabled.
- **SW-DMZ** - `global`: 'ip dhcp snooping' is not enabled.

### MEDIUM · L2-012 · Dynamic ARP Inspection is not enabled

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** Without Dynamic ARP Inspection any host can poison its neighbours' ARP caches (ARP spoofing) and sit between them and their gateway, reading or altering traffic that never leaves the VLAN, which no router ACL can see.

**Remediation.** 'ip arp inspection vlan <ids>' on VLANs whose hosts get their addresses through DHCP snooping; trust only uplinks ('ip arp inspection trust'); use ARP ACLs for statically addressed hosts.

**References.** MITRE ATT&CK T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning; Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **SW-ACCESS** - `global`: 'ip arp inspection vlan' is not configured.
- **SW-DMZ** - `global`: 'ip arp inspection vlan' is not configured.

### MEDIUM · LOG-001 · No remote syslog server

*Logging · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Without an off-box log destination the only evidence lives in volatile device memory: a reload, a full buffer or an attacker erases it, and nothing can be correlated or alerted on centrally.

**Remediation.** 'logging host <syslog-server>' with 'logging trap informational' and a stable 'logging source-interface'.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `global`: No 'logging host <address>' is configured.
- **SW-ACCESS** - `global`: No 'logging host <address>' is configured.
- **SW-DMZ** - `global`: No 'logging host <address>' is configured.

### MEDIUM · MGMT-002 · VTY access is not restricted to management hosts

*Management plane · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Without an 'access-class', every host that can route to any interface of the device may attempt to log in or exploit the management services. A management ACL shrinks that audience to a few administrator addresses.

**Remediation.** Define 'ip access-list standard VTY-MGMT' permitting only the admin host(s) and a final 'deny any log', then apply 'access-class VTY-MGMT in' on every VTY line.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `vty lines`: No effective source restriction on: line vty 0 4.
  - `L92 line vty 0 4`
- **SW-ACCESS** - `vty lines`: No effective source restriction on: line vty 0 4; line vty 5 15.
  - `L73 line vty 0 4`
  - `L77 line vty 5 15`
- **SW-DMZ** - `vty lines`: No effective source restriction on: line vty 0 4; line vty 5 15.
  - `L50 line vty 0 4`
  - `L54 line vty 5 15`

### MEDIUM · MGMT-006 · AUX port is enabled

*Management plane · 1 device(s): FW-EDGE*

**Risk.** The AUX port is an out-of-band exec path that is easy to forget. If a modem or terminal server is attached it bypasses every network control, and an unauthenticated AUX line is an open door.

**Remediation.** 'line aux 0' / 'no exec' / 'transport input none' / 'transport output none'.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `aux line`: The AUX line is not disabled ('no exec' / 'transport input none').
  - `L90 line aux 0`

### MEDIUM · MGMT-010 · SSH version 2 is not enforced

*Management plane · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Unless 'ip ssh version 2' is set, IOS also accepts the legacy SSH-1 protocol, which has known cryptographic weaknesses. If SSH is not configured at all, administrators fall back to Telnet.

**Remediation.** Set a domain name, generate an RSA key of at least 2048 bits ('crypto key generate rsa modulus 2048') and enforce 'ip ssh version 2'; add 'ip ssh time-out 60' and 'ip ssh authentication-retries 3'.

**References.** MITRE ATT&CK T1021.004 Remote Services: SSH; CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **SW-ACCESS** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).
- **SW-DMZ** - `global`: 'ip ssh version 2' is not configured (RSA key presence cannot be verified from a running-config).

### LOW · ACL-002 · Interface ACL does not end with a logged 'deny ip any any'

*Access lists · 1 device(s): FW-EDGE*

**Risk.** Packets dropped by the implicit deny at the end of an ACL are never logged, so scans and policy violations stay invisible to monitoring.

**Remediation.** End every interface ACL with 'deny ip any any log' (mind log rate limits on busy interfaces).

**References.** Cisco, Guide to Harden Cisco IOS Devices; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `ACL 101`: ACL 101 has no explicit final 'deny ip any any'; drops rely on the silent implicit deny.
  - `L84 access-list 101 permit ip any any`

### LOW · INT-001 · Proxy ARP is enabled on routed interfaces

*Interfaces · 1 device(s): FW-EDGE*

**Risk.** With proxy ARP the router answers ARP requests on behalf of other subnets. This masks misconfigured masks, lets hosts without a gateway reach other segments through the router, and widens the effect of ARP spoofing.

**Remediation.** 'no ip proxy-arp' on every routed interface or subinterface.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `interfaces`: Proxy ARP is active (default) on 6 routed interface(s).
  - `L35 interface FastEthernet0/0.10`
  - `L40 interface FastEthernet0/0.20`
  - `L45 interface FastEthernet0/0.30`
  - `L51 interface FastEthernet0/0.99`
  - `L56 interface FastEthernet0/1`
  - `L63 interface Ethernet0/1/0`

### LOW · L2-002 · Trunk ports still send DTP frames

*Layer 2 · 1 device(s): SW-ACCESS*

**Risk.** A static trunk without 'switchport nonegotiate' keeps advertising DTP, which leaks the link's role and invites negotiation attempts.

**Remediation.** Add 'switchport nonegotiate' to every static trunk.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark

- **SW-ACCESS** - `interfaces`: 1 trunk(s) lack 'switchport nonegotiate': FastEthernet0/3.
  - `L37 interface FastEthernet0/3`

### LOW · L2-004 · Trunk carries every VLAN

*Layer 2 · 1 device(s): SW-ACCESS*

**Risk.** A trunk that allows all VLANs widens broadcast domains and extends the reach of VLAN-hopping and spanning-tree attacks to VLANs that do not belong on that link.

**Remediation.** Prune each trunk: 'switchport trunk allowed vlan 10,20,99'.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark

- **SW-ACCESS** - `interfaces`: 1 trunk(s) allow all VLANs: FastEthernet0/3.
  - `L37 interface FastEthernet0/3`

### LOW · L2-010 · VTP is not in transparent or off mode

*Layer 2 · 2 device(s): SW-ACCESS, SW-DMZ*

**Risk.** In VTP server or client mode, a switch advertising a higher revision number overwrites the VLAN database of every switch in the domain - by accident or on purpose - deleting VLANs and causing an outage.

**Remediation.** 'vtp mode transparent' (or 'vtp mode off' where supported) and manage VLANs per switch.

**References.** Cisco, Guide to Harden Cisco IOS Devices; CIS Cisco IOS Benchmark

- **SW-ACCESS** - `global`: No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).
- **SW-DMZ** - `global`: No 'vtp mode transparent' or 'vtp mode off' (the default is server mode).

### LOW · LOG-002 · Log messages carry no date and time

*Logging · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Messages stamped only with uptime cannot be ordered against other systems' logs, so events cannot be correlated during an investigation.

**Remediation.** 'service timestamps log datetime msec' and 'service timestamps debug datetime msec'.

**References.** CIS Cisco IOS Benchmark

- **FW-EDGE** - `global`: 'service timestamps log datetime' is not enabled.
  - `L12 no service timestamps log datetime msec`
- **SW-ACCESS** - `global`: 'service timestamps log datetime' is not enabled.
  - `L9 no service timestamps log datetime msec`
- **SW-DMZ** - `global`: 'service timestamps log datetime' is not enabled.
  - `L7 no service timestamps log datetime msec`

### LOW · LOG-003 · No time source (NTP) is configured

*Logging · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Timestamps are only useful if every device agrees on the time; without NTP, clocks drift and logs cannot be correlated.

**Remediation.** 'ntp server <address>' (ideally authenticated with 'ntp authenticate' and 'ntp trusted-key').

**References.** CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **SW-ACCESS** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.
- **SW-DMZ** - `global`: Neither 'ntp server' nor 'ntp peer' is configured.

### LOW · MGMT-004 · No login banner

*Management plane · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Without a warning banner there is no notice that access is restricted and monitored, which weakens the basis for enforcing the acceptable-use policy. (Wording should come from your organisation's legal team.)

**Remediation.** Configure 'banner login' (or 'banner motd') with an authorised-use notice that reveals no device details.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **SW-ACCESS** - `global`: Neither 'banner login' nor 'banner motd' is configured.
- **SW-DMZ** - `global`: Neither 'banner login' nor 'banner motd' is configured.

### LOW · MGMT-009 · AAA is not enabled (local-only authentication)

*Management plane · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** Without AAA there is no central account lifecycle, command authorisation or accounting: every device keeps its own accounts and nothing records who ran which command.

**Remediation.** Enable 'aaa new-model', authenticate against TACACS+/RADIUS with a local fallback ('aaa authentication login default group tacacs+ local'), and add command accounting.

**References.** CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **SW-ACCESS** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.
- **SW-DMZ** - `global`: 'aaa new-model' is not configured; only local accounts and line passwords exist.

### LOW · SVC-001 · CDP is running

*Services · 3 device(s): FW-EDGE, SW-ACCESS, SW-DMZ*

**Risk.** CDP advertises the model, IOS version, interface names and management addresses to anything on the link, in clear text and without authentication. Attackers use it for reconnaissance, and CDP parsers have been affected by remotely exploitable bugs. The exposure matters most on ports that face users.

**Remediation.** 'no cdp run' globally, or 'no cdp enable' on every interface that does not face a trusted neighbour.

**References.** MITRE ATT&CK T1016 System Network Configuration Discovery; CIS Cisco IOS Benchmark; NSA, Network Infrastructure Security Guide

- **FW-EDGE** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 3 up interface(s).
  - `L29 interface FastEthernet0/0`
  - `L56 interface FastEthernet0/1`
  - `L63 interface Ethernet0/1/0`
- **SW-ACCESS** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 26 up interface(s).
  - `L29 interface FastEthernet0/1`
  - `L33 interface FastEthernet0/2`
  - `L37 interface FastEthernet0/3`
  - `L40 interface FastEthernet0/4`
  - `L44 interface FastEthernet0/5`
  - `L48 interface FastEthernet0/6`
  - `L52 interface FastEthernet0/7`
  - `L56 interface range FastEthernet0/8 - 24`
- **SW-DMZ** - `cdp`: CDP is globally enabled (no 'no cdp run') and active on 26 up interface(s).
  - `L21 interface FastEthernet0/1`
  - `L25 interface FastEthernet0/2`
  - `L29 interface FastEthernet0/3`
  - `L33 interface range FastEthernet0/4 - 24`
  - `L35 interface range GigabitEthernet0/1 - 2`

### LOW · SVC-002 · IP source routing is enabled

*Services · 1 device(s): FW-EDGE*

**Risk.** Source-routed packets let the sender dictate the path they take, which can bypass routing-based controls and help spoofing or firewall evasion.

**Remediation.** 'no ip source-route'.

**References.** CIS Cisco IOS Benchmark; Cisco, Guide to Harden Cisco IOS Devices

- **FW-EDGE** - `global`: 'no ip source-route' is not configured (IOS processes source-routed packets by default).
