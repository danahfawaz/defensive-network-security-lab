# References

The auditor names its sources in each finding; this page says where to find them. Existence and titles were checked on 2026-10-13. The rules are the author's reading of these documents, not a reproduction of them.

## Guidance documents

| Short name used in findings | Document | Where |
|---|---|---|
| Cisco, Guide to Harden Cisco IOS Devices | Cisco, *Guide to Harden Cisco IOS Devices* (document ID 13608) | <https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html> |
| NSA, Network Infrastructure Security Guide | NSA Cybersecurity Technical Report, *Network Infrastructure Security Guide* (March 2022) | <https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2949885/nsa-details-network-infrastructure-best-practices/> |
| NSA, Cisco Password Types: Best Practices | NSA Cybersecurity Information Sheet, *Cisco Password Types: Best Practices* (February 2022) | <https://media.defense.gov/2022/Feb/17/2002940795/-1/-1/0/CSI_CISCO_PASSWORD_TYPES_BEST_PRACTICES_20220217.PDF> |
| CIS Cisco IOS Benchmark | Center for Internet Security, *CIS Cisco IOS Benchmark* (several versions exist; the project does not claim conformance to any of them) | <https://www.cisecurity.org/benchmark/cisco> |

The Cisco and CIS addresses were taken from search results and the NSA documents from NSA's own pages; if a link has moved, search for the title.

## MITRE ATT&CK techniques cited by the auditor and the threat model

All of these were opened on attack.mitre.org on 2026-10-13 and the identifiers and names match.

| ID | Name |
|---|---|
| T1016 | System Network Configuration Discovery |
| T1021.004 | Remote Services: SSH |
| T1040 | Network Sniffing |
| T1078 | Valid Accounts |
| T1078.001 | Valid Accounts: Default Accounts |
| T1110.001 | Brute Force: Password Guessing |
| T1190 | Exploit Public-Facing Application |
| T1200 | Hardware Additions |
| T1498 | Network Denial of Service |
| T1552.001 | Unsecured Credentials: Credentials In Files |
| T1557 | Adversary-in-the-Middle |
| T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning |
| T1602.001 | Data from Configuration Repository: SNMP (MIB Dump) |

Pattern: `https://attack.mitre.org/techniques/<ID>/` with a `/` instead of `.` before the sub-technique number (for example `T1021/004`).
