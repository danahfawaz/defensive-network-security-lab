# Enterprise Network Security & Configuration Auditing Lab

A segmented enterprise network (firewall router, DMZ, guest, management and server zones) designed for Cisco Packet Tracer, together with **`ciscoaudit`**, a Python tool that audits Cisco IOS configurations for insecure settings and **checks that the network's access lists really implement a written security policy**.

It started as a flat university lab (four routers, three switches, no passwords, no VLANs, no ACLs) and was redesigned, hardened, audited and tested. Every claim below can be reproduced with one command, and anything that could not be verified is labelled as such.

![Topology](docs/generated/topology.svg)

## What has been verified, and what has not

| | Status |
|---|---|
| Auditor (52 rules), parser, ACL model, waivers, reports | **Tested**: 300+ unit tests, including tests against deliberately broken configurations |
| Hardened configurations implement the written policy | **Verified by simulation**: 124 scenarios and a 3 146-probe reachability matrix, computed from the configuration text by this repository's policy simulator |
| Packet Tracer accepts and enforces the configurations | **Not yet verified.** The tests were not run in Packet Tracer; 20 groups of configuration lines are marked `[PT-VERIFY]` (the rest is standard IOS syntax that has not been run in Packet Tracer either), and the Packet Tracer column of every report says *pending*. The generated [test plan](docs/pt-test-plan.md) and [build guide](docs/packet-tracer-build.md) are how to close this gap. |
| Screenshots | **None are committed**, because none have been taken. Real tool output is shown below as text. |

The simulator says what the *configuration* does. It is not Packet Tracer, and its results are not presented as Packet Tracer results. See [docs/validation.md](docs/validation.md) and [docs/limitations.md](docs/limitations.md).

## Results (computed, reproducible)

| Audit of | Open findings | Critical | High | Medium | Low | Accepted risk |
|---|---:|---:|---:|---:|---:|---:|
| Original university lab (7 devices) ¹ | 150 | 0 | 18 | 65 | 67 | 0 |
| Redesigned network, **baseline** configuration | 65 | 3 | 7 | 33 | 22 | 0 |
| Redesigned network, **hardened** configuration | **0** | 0 | 0 | 0 | 0 | 5 (documented, expiring) |

| Policy check on the hardened configuration | Result |
|---|---|
| Scenarios (business flows, attacks, spoofing, management, Layer 2, hygiene, limitations) | 115 passed, 0 failed, 9 pending Packet Tracer |
| Reachability matrix: probes that disagree with the written policy | 0 of 3 146 (the baseline lets 1 447 probes cross zones; the hardened network 87) |
| Mutation tests: validators fail when a control is removed | yes: see `tests/test_scenarios.py`, `tests/test_matrix.py` |

¹ Of the 150 original findings, 85 belong to devices that the new design no longer has (Router2, Router3, Router4, Switch2); `compare` reports them as *left scope*, not as fixed. See [`evidence/audit/compare-original-to-hardened.md`](evidence/audit/compare-original-to-hardened.md).

Full outputs: [`evidence/`](evidence/README.md).

## What is in the network

| Zone | VLAN / subnet | May do |
|---|---|---|
| Users | 10 · 10.10.10.0/24 | Use the internal app and the public web server, resolve names, browse the Internet (PAT) |
| Servers | 20 · 10.10.20.0/24 | Answer employees; resolve names |
| Guest | 30 · 10.10.30.0/24 (DHCP) | Internet and DNS only |
| Management | 99 · 10.10.99.0/24 | The administrator workstation is the only host allowed to manage devices (SSH) |
| DMZ | 50 · 172.16.50.0/24 | Public web (80/443) and DNS (53) via static NAT; one controlled flow to the app server |
| Internet (simulated) | 198.51.100.0/24 | A legitimate client and an attacker (`PC5`) |

Controls: one enforcement point (FW-EDGE) with default-deny inbound ACLs and logged denies; anti-spoofing; static NAT + PAT; SSH-only management restricted by an access class; a local administrator account and hashed secrets; DTP off, native VLAN 999, port security, BPDU Guard, parked unused ports, DHCP snooping and ARP inspection on the guest VLAN; syslog and NTP. Details: [docs/architecture.md](docs/architecture.md). Threats and how each is tested: [docs/threat-model.md](docs/threat-model.md).

## Quick start

Requires Python 3.11+ and PyYAML (`pip install pyyaml`). No network access is needed.

```bash
export PYTHONPATH=src                                   # or: pip install -e .

python -m ciscoaudit audit configs/baseline -v          # find the insecure settings
python -m ciscoaudit audit configs/hardened --waivers waivers/hardened.yaml
python -m ciscoaudit validate --state hardened          # 124 scenarios
python -m ciscoaudit trace "PC5 -> 203.0.113.9 tcp/22"  # explain one flow hop by hop
python -m ciscoaudit matrix                             # every sender x destination x service vs. the written policy
python -m ciscoaudit rules                              # what is checked

make all                                                # everything above plus the unit tests and the consistency checks
```

### Example: auditing the baseline firewall (excerpt of the real output)

```text
$ python -m ciscoaudit audit configs/baseline/FW-EDGE.cfg -v
CRITICAL CRED-004  FW-EDGE: A well-known or default password is in use
          Matches the built-in list of well-known passwords (the value is deliberately not shown): enable password, line con 0, line vty 0 4.
           L18 enable password <redacted>
           fix: Replace the credential with a unique passphrase (14+ characters) and rotate anything derived from it.
HIGH     MGMT-001  FW-EDGE: Telnet is accepted for remote management
          Telnet is permitted on: line vty 0 4 (no 'transport input': IOS default accepts Telnet).
           fix: Allow only SSH on the VTY lines: 'line vty 0 15' / 'transport input ssh'.
HIGH     MGMT-005  FW-EDGE: HTTP management server is enabled
MEDIUM   ACL-001   FW-EDGE: ACL contains a 'permit any any' entry
          'access-list 101 permit ip any any' permits all traffic after some deny entries (blocklist style).
```

### Example: why an attack fails (excerpt of the real output)

```text
$ python -m ciscoaudit trace "PC5 -> 203.0.113.9 tcp/22" --state hardened
[hardened] PC5 -> 203.0.113.9 tcp/22
  request denied at FW-EDGE: Ethernet0/1/0 in ACL IN-OUTSIDE: 'deny ip any any log' (line 204)
     1. PC5: sends to its gateway ISP-R FastEthernet0/0 (198.51.100.1)
     2. ISP-R: FastEthernet0/0 in: no ACL, everything is permitted
     3. ISP-R: 203.0.113.9 via static route 203.0.113.8/29 -> FastEthernet0/1, next hop 203.0.113.2
     4. ISP-R: forwards to FW-EDGE Ethernet0/1/0 (203.0.113.2)
     5. FW-EDGE: Ethernet0/1/0 in: ACL IN-OUTSIDE denies - 'deny ip any any log' (line 204)
```

### Example: scenarios

```text
$ python -m ciscoaudit validate --state hardened
P-01  permitted   hard PASS    delivered                       Employee opens the internal application over HTTPS
B-01  blocked     hard PASS    blocked (IN-GUEST @ FW-EDGE)    Guest device reaches the application server
B-22  blocked     hard PASS    blocked (IN-OUTSIDE @ FW-EDGE)  Internet attacker tries SSH to the public web server
S-01  spoofing    hard PASS    blocked (IN-OUTSIDE @ FW-EDGE)  Internet attacker forges an internal (10.0.0.0/8) source address
M-01  management  hard PASS    blocked (vty @ SW-ACCESS)       Non-administrator host in the Management VLAN opens SSH to the access switch
```

(The lines are excerpts of real output; each report carries the full list.)

## The auditor

* 52 rules in nine categories (access control, credentials, management plane, access lists, Layer 2, services, routing, logging, interfaces), each with a risk statement, remediation and references ([catalogue](docs/generated/rules.md), [sources](docs/references.md)).
* Structured output: text, JSON, Markdown, CSV; known credential forms (see `tests/test_redact.py`) are redacted before they enter any finding.
* Accepted risks are **waivers** that keep the finding visible, require a reason and expire.
* `compare` shows what a remediation changed and refuses to count a decommissioned device as a fix.
* Standard library + PyYAML. Design and testing: [docs/auditor.md](docs/auditor.md).

## Validation approach

1. `design-check`: the configurations implement `topology/topology.yaml`.
2. `audit`: no open findings on the hardened configurations.
3. `validate`: each named business flow works and each named attack fails *for the stated reason* (which ACL, on which device).
4. `matrix`: nothing else gets through *among the 11 probed services and 27 probed addresses* (same-VLAN traffic is out of scope); probes include unused addresses so subnet-wide rules are caught.
5. Packet Tracer: **pending**; generated plan and a results sheet with `pt-compare` to measure agreement with the simulator.

## Repository layout

```
src/ciscoaudit/      auditor + policy simulator (parser, acl, rules/, waivers, compare, policy/)
configs/             original-lab/  baseline/  hardened/  internet-sim/   (placeholder secrets only)
topology/            topology.yaml (the design), policy-intent.yaml (the written policy)
scenarios/           124 validation scenarios
waivers/             accepted risks, each with reason and expiry
scripts/             render_configs.py (your own passwords), generate_docs.py, make_evidence.py
docs/                architecture, threat model, validation, limitations, auditor, build guide, PT test plan
evidence/            committed tool outputs; evidence/packet-tracer/ is for your own results
tests/               unit tests
```

## Building it in Packet Tracer

The committed configurations hold **placeholder hashes** instead of passwords. `python scripts/render_configs.py --generate` writes paste-ready copies with passwords you choose to a git-ignored folder. The [build guide](docs/packet-tracer-build.md) walks through cabling, host settings, pasting, RSA key generation and the test plan.

## Limitations

Stateless router ACLs, no filtering inside a VLAN, an in-band-managed DMZ switch, no AAA server, and a simulator that models configuration, not Packet Tracer. The full list, with the scenarios that pin each one down, is in [docs/limitations.md](docs/limitations.md). A real deployment would use a stateful firewall, TACACS+/RADIUS and an IPS.

## Origin and licence

This began as a university Cisco Packet Tracer course project. The original project file and course documents are not part of this repository; only the configurations of its devices (default names, no secrets) are kept as the "Day 0" state. Released under the [MIT License](LICENSE).
