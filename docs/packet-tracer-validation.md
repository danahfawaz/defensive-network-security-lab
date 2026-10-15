# Manual Packet Tracer validation

The hardened configurations were built and tested by hand in Cisco Packet Tracer. Nine checks (X-01 to X-09) cover the controls whose behaviour is only visible on running devices: DHCP, SSH, port security, NAT, ACL enforcement, syslog/NTP, the running configuration, DHCP snooping and Dynamic ARP Inspection.

* Packet Tracer version: 9.0.1 (64-bit)
* Date of the run: 2026-10-15
* Configurations used: `configs/hardened/` and `configs/internet-sim/`, pasted with lab passwords chosen by the author ([build guide](packet-tracer-build.md)).
* Topology and addressing: [addressing](generated/addressing.md), [cabling](generated/cabling.md).
* Results sheet: [`evidence/packet-tracer/results.csv`](../evidence/packet-tracer/results.csv).

## Result: 9 of 9 checks passed

| ID | Control | Where | What was done | Observed |
|---|---|---|---|---|
| X-01 | DHCP for the guest VLAN | PC2 | Set to DHCP | 10.10.30.100/24, gateway 10.10.30.1, DNS 172.16.50.20 |
| X-02 | SSH-only management | PC3 → FW-EDGE | SSH login, then Telnet; `show ip ssh` | SSH login succeeded; Telnet was blocked; SSH version 2 enabled |
| X-03 | Port security | SW-ACCESS Fa0/1 | Connected a second MAC address | `PORT_SECURITY-2-PSECURE_VIOLATION` logged; the port entered err-disabled |
| X-04 | NAT / PAT | FW-EDGE | Internal host to the external web server; Internet host to the DMZ web server; `show ip nat translations` | Both connections succeeded; static and dynamic translations listed |
| X-05 | Default-deny ACL on the outside interface | PC5 (Internet attacker) | Eight unauthorised attempts (below) | All eight blocked |
| X-06 | Syslog and NTP | SRV-LOG, FW-EDGE, SW-ACCESS | Generated a syslog event on SW-ACCESS; `show ntp status` | SRV-LOG received the event; both devices: clock synchronized, stratum 2, reference 10.10.99.20 |
| X-07 | Running configuration | FW-EDGE, SW-ACCESS, SW-DMZ | `show running-config` | Retrieved and verified on all three devices; exports are in [`evidence/packet-tracer/exported/`](../evidence/packet-tracer/exported) with every password hash replaced by `XXXX` |
| X-08 | DHCP snooping | SW-ACCESS Fa0/10 | Temporary rogue DHCP server on VLAN 30; renewed PC2's lease; `show ip dhcp snooping` | PC2 kept the legitimate configuration; snooping enabled on VLAN 30; Fa0/10 untrusted, Fa0/3 trusted, Fa0/4 untrusted with a rate limit |
| X-09 | Dynamic ARP Inspection | SW-ACCESS | `show ip arp inspection` | DAI enabled and active on VLAN 30 |

### X-05: traffic blocked from the Internet attacker (PC5)

| Attempt | Result |
|---|---|
| Telnet to 203.0.113.2 (firewall) | blocked |
| HTTP to 203.0.113.2 | blocked |
| ICMP to 203.0.113.2 | blocked |
| SSH to 203.0.113.9 (public web server) | blocked |
| ICMP to 203.0.113.9 | blocked |
| TCP/3389 to 203.0.113.9 | blocked |
| SNMP (UDP/161) to 203.0.113.10 (public DNS server) | blocked |
| ICMP to internal host 10.10.10.10 | blocked |

Enforcement is evidenced by the blocked traffic itself. The ACL output in Packet Tracer did not display deny hit counters; the exported configuration shows why: it holds no explicit `deny` entries (see the notes below), so the default-deny behaviour came from the implicit deny at the end of each ACL, which has no counter.

### Scope of X-07 and X-09

* X-07 covers the running configurations of the three audited devices: they were retrieved, the auditor was run on them ([export-audit.md](../evidence/packet-tracer/export-audit.md): 0 critical and 0 high findings) and they were compared with the intended configurations ([export-comparison.md](../evidence/packet-tracer/export-comparison.md)).
* X-09 records the configuration and operational status of DAI on VLAN 30. No live ARP-spoofing attack was run.

## Notes on the Packet Tracer running configuration

Some pasted commands produced `% Invalid input` in Packet Tracer; which ones was not recorded line by line, so the reasons are not stated here. The comparison of the exports with the intended configurations ([export-comparison.md](../evidence/packet-tracer/export-comparison.md)) shows exactly what the running configurations contain:

* **Present:** the VLANs, trunk and access ports, port security, DHCP snooping and Dynamic ARP Inspection, SSH version 2 with `transport input ssh` and the `VTY-ADMIN` access class, `login block-for`, static NAT and PAT, the discard route (`Null0`) for the public block, the permit entries of all six interface ACLs (one ICMP `time-exceeded` entry on `IN-OUTSIDE` excepted), syslog and NTP.
* **Not present:** every ACL entry that uses the `log` keyword (30 entries: the anti-spoofing denies, the explicit final `deny ip any any log` of each ACL and the final deny of each VTY access list), `no service pad`, `no ip redirects`, `no ip unreachables`, `logging trap`, `logging source-interface`, `logging buffered`, `ip ssh authentication-retries`, `no exec` on the AUX line, and the `privilege 15` keyword on the switches' admin account. Settings equal to the IOS default (for example `port-security maximum 1`) are normally not printed in a running configuration.

What this means for the results:

* The permit entries and the implicit deny enforce the same default-deny policy, which is what X-04 and X-05 observed.
* The anti-spoofing denies (scenarios S-01 to S-10) are demonstrated by the policy simulator; no stock Packet Tracer PC tool forges a source address, so they are not part of the Packet Tracer checks.
* Lines that were not individually tested are not claimed to work; the per-line list is [pt-verify](generated/pt-verify.md).

## How this fits with the other two layers

| Layer | Source of the result | Where |
|---|---|---|
| Automated configuration auditing | `ciscoaudit audit`, computed from configuration text | [auditor](auditor.md), `evidence/audit/` |
| Policy simulation | `ciscoaudit validate` / `matrix`, computed from configuration text | [validation](validation.md), `evidence/validation/`, `evidence/policy-matrix/` |
| Manual Packet Tracer validation | Observed by the author in Packet Tracer | this page, `evidence/packet-tracer/` |

For every flow the Packet Tracer checks exercised (X-02, X-04, X-05), the simulator predicted the same outcome (allowed or blocked) that was observed. The other traffic scenarios of the [test plan](pt-test-plan.md) were not run one by one in Packet Tracer; they remain simulation results.
