# Validation: how the design is tested, and what the tests prove

> **Read this first.** Everything marked *simulated* below is computed by the project's own tools from the configuration files. None of it was produced by Packet Tracer. Packet Tracer results are *pending* until you run the [test plan](pt-test-plan.md).

## Four layers

| Layer | Tool | Question answered | Result today |
|---|---|---|---|
| 1. Design consistency | `ciscoaudit design-check` | Do the configurations implement `topology.yaml` (addresses, VLANs, ports, trunks, NAT)? | OK for baseline and hardened (14 checks each) |
| 2. Configuration audit | `ciscoaudit audit` | Which insecure settings are present? | Hardened: **0 open**, 5 accepted risks. Baseline: 65 open (3 critical, 7 high) |
| 3. Policy scenarios | `ciscoaudit validate` | Does each named attack fail and each business flow work? | Hardened: **115 passed, 0 failed**, 9 pending (Packet Tracer). Baseline: 95 asserted pass, 20 informational, 9 pending |
| 4. Exhaustive matrix | `ciscoaudit matrix` | Is *anything else* permitted that the written policy does not list? | Hardened: **0 unexpected permits, 0 unexpected blocks** in 3 146 probes. Baseline: 1 447 probes cross zones against 87 hardened |

The committed outputs are in `evidence/` (see its README). Reproduce everything with `make all` and `make evidence`.

## Layer 3: scenarios

`scenarios/scenarios.yaml` holds 124 scenarios in eight categories:

| Category | Count | Purpose |
|---|---|---|
| permitted | 30 | The business keeps working (employee → application, guest → Internet, Internet → public web, ...). A hardening that breaks the network is a failure. |
| blocked | 36 | Attacks that must fail (guest → servers, Internet → internal, compromised DMZ server → inside, ...). Each names *which* ACL on *which* device stops it. |
| spoofing | 10 | Forged source addresses from the Internet and from inside zones. |
| management | 16 | Who may reach SSH/Telnet/HTTP on the devices, including defence in depth against a crafted ACK. |
| layer2 | 8 | Layer-2 controls, judged by auditor rules on the configuration text. |
| hygiene | 7 | Audit properties: no default credentials, SSH-only, timeouts, logging, ACL hygiene. |
| limitation | 8 | Documented weaknesses, asserted so they cannot change silently (e.g. a crafted ACK passes the stateless ACL). |
| manual | 9 | Need Packet Tracer (DHCP lease, SSH login, port-security shutdown, NAT table, DHCP snooping, DAI, ...); reported as *pending*. |

Each flow scenario is judged by the policy simulator and states the expected outcome for the hardened configuration; many also state the baseline outcome, so the before/after contrast is itself asserted. For a blocked flow the scenario also states `by` (ACL, route, vty or no-service) and `at` (device), so a test fails if a flow is blocked **for the wrong reason**.

```bash
python -m ciscoaudit validate --state hardened -v          # all scenarios
python -m ciscoaudit validate --only "B-2*" --verbose      # a group, with hop-by-hop traces
python -m ciscoaudit trace "PC5 -> 203.0.113.9 tcp/22" --state both
```

Example (`trace`, hardened): the packet from the attacker follows ISP-R's route for the public block to FW-EDGE `Ethernet0/1/0`, where `IN-OUTSIDE` has no permit for tcp/22 to `203.0.113.9`; the final `deny ip any any log` drops it and the trace names the ACL and its line.

### The simulator

`src/ciscoaudit/policy/engine.py` walks a packet hop by hop: ingress ACL → static destination NAT → local delivery (ICMP echo, DHCP, SSH/Telnet access class, HTTP server) or routing (connected, static, `Null0`, recursive next hop) → PAT / static source NAT → egress ACL → next device, then builds the **reply** the same way, because many mistakes (a missing `established` entry) only show up on the way back. It reuses the auditor's ACL parser. What it does not model is listed in [limitations](limitations.md).

## Layer 4: the matrix

Hand-picked attacks show that *those* attacks fail. They cannot show that nothing else gets through. `ciscoaudit matrix` probes every sender (11 hosts) against every destination (27 addresses, including each interface of the firewall, the public NAT addresses and one **unused** address beside every server segment) for 11 services, and compares the answer with the flows that `topology/policy-intent.yaml` lists. The unused addresses exist to catch rules written for a whole subnet when one host was meant.

* *Unexpected permit* = the request of a flow the policy does not list reaches its destination (a hole, even if the reply is dropped).
* *Unexpected block* = a listed flow does not work as a round trip (a broken service).
* Traffic inside one VLAN never meets the firewall; it is counted separately and documented as a limitation (220 of the 307 permitted hardened probes).

The simulator and the matrix found real defects in the first hardened draft, all fixed in the configuration (see the Git history): the replies to the administrator's ping and the NTP reply to the firewall were blocked (found by the scenarios and the simulator), and several ICMP rules were written for a whole subnet, one of them letting Users ping the firewall's outside address and the DMZ switch (found by the matrix).

## Do the tests really test anything?

Tests of the tests (`tests/test_scenarios.py`, `tests/test_matrix.py`, `tests/test_policy_engine.py`) copy the configurations to a temporary directory, **break them on purpose**, and assert that the validators notice: remove the anti-spoofing entries, open a zone with `permit ip any any`, remove a reply (`established`) rule, remove the VTY access class, remove static NAT or the discard route, leave a referenced ACL undefined, shut a zone interface, write a subnet-wide permit, or secure the baseline (which must make the baseline assertions fail). If a mutation is *not* detected, the test fails.

## What this does and does not prove

| It shows | It does not show |
|---|---|
| The configuration text, as written, implements the policy: allowed flows work, listed attacks fail, nothing unlisted passes (under the simulator's model) | That Packet Tracer accepts every line or enforces it identically |
| The auditor finds the weaknesses it has rules for, and the baseline → hardened comparison is computed | That the rules are complete; a clean audit means "none of these 52 checks fired" |
| Limitations are asserted, so they are visible | Anything about stateful behaviour, host firewalls, applications or DoS |

## Closing the gap with Packet Tracer

1. Build the lab ([build guide](packet-tracer-build.md)) and run the [test plan](pt-test-plan.md). Record results in `evidence/packet-tracer/results.csv`.
2. `python -m ciscoaudit pt-compare evidence/packet-tracer/results.csv` reports, per scenario, agreement, disagreement, *not supported in Packet Tracer* or *not run*.
3. Every disagreement is a finding about either the simulator or Packet Tracer; write it into [limitations](limitations.md).
