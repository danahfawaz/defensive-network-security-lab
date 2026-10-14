# Limitations and accepted risks

This page lists what the project does **not** do or prove. It exists so that nobody (including an interviewer) has to find these by accident. Each item says where it shows up in the scenarios or waivers.

## 1. What has and has not been verified

| Claim | Status |
|---|---|
| The auditor finds the insecure settings it has rules for | **Verified** by 300+ unit tests, including tests against deliberately broken configurations |
| The hardened configuration files implement the written policy | **Verified by simulation**: 115 scenarios and the 3 146-probe matrix are computed from the configuration text |
| Packet Tracer 9.0 accepts every command in the hardened configurations | **Not verified.** 20 groups of lines are marked `[PT-VERIFY]` ([list](generated/pt-verify.md)); the rest were written from standard IOS syntax and the original lab's exported configurations |
| Packet Tracer enforces the ACLs, NAT, port security, DHCP snooping, DAI as the simulator assumes | **Not verified.** The 9 `X-nn` scenarios and the whole [test plan](pt-test-plan.md) are *pending* |
| Screenshots | None are committed. They are added only after the test plan has been run in Packet Tracer |

The simulator models **what the configuration says**, not what Packet Tracer does. A disagreement between the two is a result worth recording (`ciscoaudit pt-compare`), not an error to hide.

## 2. Network design

| Limitation | Why | Where it appears |
|---|---|---|
| **Stateless ACLs.** `established` matches any segment with ACK or RST set. A crafted packet with the ACK flag passes the entries that exist for replies. | Router ACLs on a 1841 have no connection table. A real design would use a stateful firewall (ASA/FTD, or Zone-Based Firewall on IOS where the platform supports it). Zone-Based Firewall and CBAC were not used because their support in Packet Tracer was not verified. | K-01, K-02, K-03, T11; scenario M-16 shows the SSH access class still refuses such a packet |
| **No filtering inside a VLAN.** Hosts in the same VLAN reach each other directly. | Needs private VLANs or port ACLs, which the lab does not use. | K-05, K-06, M-14, M-15 |
| **DMZ switch is managed in-band** on the DMZ VLAN (`172.16.50.2`). | The 2960 has no separate management port; putting its address in VLAN 99 would need another trunk to the DMZ. A compromised DMZ server can therefore reach it at Layer 2. SSH-only and `VTY-ADMIN` limit the exposure. | Waivers `MGMT-009`, `L2-011`, `L2-012` on SW-DMZ |
| **No hairpin NAT, no split DNS.** Employees must use the web server's private address; the Internet uses the public one. | The router does not translate inside-to-public-block traffic. | K-04 |
| **No central AAA.** Local accounts only. | A TACACS+/RADIUS server was out of scope. | H-08; waiver `MGMT-009` on all three devices |
| **No IPv6, wireless, VPN, IPS, TLS inspection, DoS protection.** | Out of scope for the MVP. | [Threat model](threat-model.md) |
| **One firewall, one ISP link.** | No redundancy, no failover. | – |

## 3. The policy simulator (`ciscoaudit validate`, `trace`, `matrix`)

Models: ingress ACL, static destination NAT, PAT, routing (connected, static, `Null0`), egress ACL, device-local services (ICMP echo, DHCP pool, SSH/Telnet access class, HTTP server), reply path.

Does **not** model: TCP state or flags beyond the `established` match, fragments, ICMP errors, ARP and DHCP exchanges, host firewalls and services (a server answering is assumed), ACL logging, QoS, spanning tree, port security, DHCP snooping, DAI. Layer-2 controls are judged by the auditor from configuration text only.

ACL entries the model cannot judge (TCP flag matches such as `syn`, `fragments`, `time-range`, DSCP/precedence, or syntax it does not parse) make the simulator **stop with an error** instead of skipping them, because skipping a `deny` would give a false "permitted" or "blocked". The hardened configurations use none of them.

Same-subnet traffic is treated as switched and never filtered. If a destination address has no owner the simulator says so and stops; it does not guess.

## 4. The auditor (`ciscoaudit audit`)

* Reads text exported from IOS 12.4 / 15.0 style routers and switches. IOS-XE, NX-OS, ASA and others are not supported and unknown ACL syntax is reported as `ACL-008` (info) rather than ignored.
* Judges configuration text, not running state: it cannot tell whether an interface is really up, whether a key pair exists (exported configurations do not contain RSA keys), or whether a feature works.
* Rules and severities are the author's interpretation of public guidance (see [auditor](auditor.md)); they are not the CIS Benchmark and do not replace a commercial scanner.
* Redaction removes secrets from reports, but `type 7` strings are reversible by design. The auditor decodes them only to judge their strength and flags them.

## 4a. Behaviours worth knowing about

* `login block-for 120 attempts 3 within 60` on FW-EDGE throttles brute-force attempts but also locks the administrator out for two minutes after three failed logins (`login quiet-mode access-class` could exempt the management host; not used because it is another unverified line).
* `ACL-001` (permit any any) reports only ACLs that are *applied*; an unapplied one is reported as `ACL-005` (low).
* `tests/fixtures/secrets_router.cfg` contains the well-known Cisco example strings (`cisco`, `0822455D0A16`). They are synthetic; a secret scanner will flag them and should allow-list the file.

## 5. Secrets and personal data

* The committed configurations contain placeholder hashes only (`$1$labonly$…`). Real lab passwords are generated locally by `scripts/render_configs.py` into git-ignored files.
* The baseline configurations deliberately use the weak well-known password `cisco`, because the auditor must have something to find. They are not used on any real system.
* The original `.pkt` file and any university documents are not part of the repository.

## 6. Reproducibility

* The evidence in `evidence/` was produced by the commands in the README with the date pinned (`--today`) so that waiver expiry gives identical output. Regenerate with `make evidence`.
* The committed audit of the **hardened** configurations is an audit of the *intended* configuration files, not of a device exported from Packet Tracer. Step 7 of the [build guide](packet-tracer-build.md) produces the latter.
