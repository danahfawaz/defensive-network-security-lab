# Threat model

A small, explicit threat model: who could attack this network, from where, what the design does about it, and what is left. Every threat has an identifier (T01–T12). The validation scenarios in `scenarios/scenarios.yaml` carry the identifiers of the threats they test, and [generated/threat-coverage.md](generated/threat-coverage.md) lists them per threat, so a threat without a test is visible.

> Scope: the lab is a Packet Tracer simulation of a small enterprise. The model covers network-level threats that routers, switches and access lists can influence. It does not cover endpoint compromise, application vulnerabilities, social engineering or denial of service.

## Assets and zones

| Asset | Where | Why it matters |
|---|---|---|
| Internal application (SRV-APP) | Servers VLAN 20 | Business data; must be reachable by employees only |
| Network devices (FW-EDGE, SW-ACCESS, SW-DMZ) | Management VLAN 99 / DMZ | Whoever controls them controls every other asset |
| Log and time server (SRV-LOG) | Management VLAN 99 | Evidence of what happened; must not be tampered with from the user networks |
| Public servers (WEB-DMZ, DNS-DMZ) | DMZ VLAN 50 | Exposed to the Internet, therefore the most likely first foothold |
| Employee and administrator workstations | Users VLAN 10 / Management VLAN 99 | Typical pivot point; the administrator workstation is the only trusted management source |

Trust levels, from least to most trusted: Internet → Guest → DMZ → Users → Servers → Management. The firewall (FW-EDGE) is the only router between zones; see [architecture](architecture.md).

## Attacker profiles

| Profile | Starts at | Capability assumed |
|---|---|---|
| Internet attacker | PC5 (198.51.100.66) | Can send any packet to the public addresses, including forged source addresses |
| Guest user | PC2 (Guest VLAN) | Authorised for Internet only; may be curious or hostile; can attach tools to the network |
| Compromised employee workstation | PC0/PC1 | Full control of one Users host |
| Compromised public server | WEB-DMZ / DNS-DMZ | Full control of one DMZ host (the usual result of a web vulnerability) |
| Insider with physical access to a wall port | Any unused or edge port | Can plug in a laptop, a switch or a rogue DHCP server |

## Threats

| ID | Threat | Attacker and path | Main controls | ATT&CK reference |
|---|---|---|---|---|
| T01 | Guest users reach internal systems | Guest user → Users, Servers, Management, DMZ | Dedicated VLAN 30; `IN-GUEST` allows only DHCP, DNS to the DMZ resolver and web/ping to the Internet; DHCP snooping and ARP inspection on the Guest VLAN | – |
| T02 | Lateral movement from a compromised workstation | Compromised employee workstation → servers, management, other zones | `IN-USERS` allows only HTTP/HTTPS/ping to the listed servers, DNS to the DMZ resolver and web out; no route to Management or Guest | – |
| T03 | Unauthorised remote administration of network devices | Anyone → SSH/Telnet/HTTP on a router or switch | SSH version 2 only (`transport input ssh`), a local `admin` account (one shared account per device; no AAA), `VTY-ADMIN` access class (administrator workstation only), `no ip http server`, ACLs refuse management protocols from other zones, idle time-out | T1021.004 Remote Services: SSH |
| T04 | Attack on the perimeter and published services | Internet attacker → firewall, DMZ servers, internal addresses | `IN-OUTSIDE` default deny: only HTTP/HTTPS to the public web address and DNS to the public DNS address; static NAT hides private addresses; no route to RFC 1918 from the ISP; discard route for the unused public block | T1190 Exploit Public-Facing Application |
| T05 | Pivoting from a compromised DMZ server | DMZ server → inside networks, other DMZ hosts, Internet | `IN-DMZ`: DMZ hosts only answer requests; the one connection a DMZ server may start towards the inside is WEB-DMZ → SRV-APP (HTTP), and the DMZ switch may send syslog/NTP to the log server; all other private destinations are denied and logged | – |
| T06 | Address spoofing | Any zone → forged source address | Anti-spoofing denies at the top of `IN-OUTSIDE` (private, loopback, reserved, the organisation's own public addresses); per-zone ACLs permit only that zone's own source subnet | – |
| T07 | Data exfiltration and unwanted outbound traffic | Compromised host → Internet | Only Users and Guest may leave, and only HTTP/HTTPS/ping (PAT); servers and management have no outbound path, and DMZ servers can only answer requests (they may not start connections) | – |
| T08 | Layer-2 attacks | Insider on a switch port → VLAN hopping, MAC flooding, STP manipulation, rogue DHCP, ARP spoofing | DTP off (`nonegotiate`), native VLAN 999, allowed-VLAN list on trunks, port security with sticky MAC (maximum 1, shutdown), PortFast + BPDU Guard, VTP transparent, DHCP snooping and DAI on the Guest VLAN | T1557.002 ARP Cache Poisoning |
| T09 | Insecure device configuration | Any attacker who finds weak credentials or open services | The auditor (`ciscoaudit`, 52 rules): encrypted secrets, no default passwords, no HTTP server, no CDP, time-outs, banners, ACL hygiene; waivers must be justified and expire | – |
| T10 | No visibility | Attacker acts without leaving evidence | Syslog (informational) and NTP to SRV-LOG; time stamps; `log` on deny entries so ACL counters and logs show attempts | – |
| T11 | Stateless ACL evasion | Attacker crafts packets with the ACK flag or a source port that matches `established` or reply rules | Documented limitation; compensating controls are the per-destination host entries and the SSH-only VTY access class (scenario M-16 shows a crafted ACK still cannot open a management session) | – |
| T12 | Rogue device on an unused or edge port | Insider plugs in a laptop or a switch | Unused ports shut down and parked in VLAN 999; port security limits MAC addresses on edge ports; BPDU Guard | T1200 Hardware Additions |

ATT&CK references were checked against attack.mitre.org on 2026-10-13. Only techniques that clearly describe the threat are listed; "–" means no mapping is claimed.

## What is deliberately out of scope or accepted

| Item | Treatment |
|---|---|
| Stateless filtering | Router ACLs do not track connections. See [limitations](limitations.md) (T11). |
| Traffic inside one VLAN | Switched, never filtered; no private VLANs or port ACLs. Accepted; documented. |
| DMZ switch managed in-band | Its address is in the DMZ VLAN, so a compromised DMZ server can reach it at Layer 2. SSH-only and `VTY-ADMIN` limit the exposure. Waivers `MGMT-009`, `L2-011`, `L2-012` record the decision. |
| No AAA server | Local accounts only (finding `H-08`). A production network would use TACACS+ or RADIUS. |
| Denial of service | Not modelled. |
| Encrypted-traffic inspection, IPS, application-layer filtering | Not available on the devices used. |

## How the threats are tested

* **Simulation:** `ciscoaudit validate` runs 124 scenarios against the configuration files; `ciscoaudit matrix` probes 3 146 sender/destination/service combinations per state against the written policy. Both are computed from the configuration text and are **not** Packet Tracer results. See [validation](validation.md).
* **Auditing:** the 52 auditor rules cover T03, T08, T09, T10 and T12 directly from the configuration text.
* **Packet Tracer:** the generated [test plan](pt-test-plan.md) lists what to do in Packet Tracer for each scenario. Until it has been executed, the Packet Tracer column of every result is *pending*.
