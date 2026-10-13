# The Cisco configuration security auditor (`ciscoaudit`)

A command-line tool that reads exported Cisco IOS configurations, reports insecure settings with the risk and the fix, and can show what a remediation changed. Python 3.11+, standard library plus PyYAML (used only for waivers and scenario files). Source: `src/ciscoaudit/`.

```bash
pip install pyyaml                               # no other dependency
export PYTHONPATH=src                            # or: pip install -e .
python -m ciscoaudit audit configs/baseline -v   # text report with evidence and remediation
python -m ciscoaudit audit configs/hardened --waivers waivers/hardened.yaml --fail-on info
python -m ciscoaudit audit configs/baseline -f markdown -o report.md
python -m ciscoaudit rules --category "Layer 2"  # what is checked
```

Formats: `text`, `json` (the stable machine-readable form; `compare` consumes it), `markdown`, `csv`. Exit status: `0` clean (or below `--fail-on`), `1` open findings at or above `--fail-on`, `2` bad input.

## How it works

```
 .cfg text ──► parser ──► DeviceConfig ──► rules (52) ──► findings ──► redaction ──► reports
                 │            │                │                │
   global lines, │  helpers:  │   each rule is │  waivers add   │  secrets never reach
   interfaces,   │  state(),  │  a function    │  status +      │  evidence or output
   line blocks,  │  ACL model │  returning     │  reason        │
   ACL entries   │            │  Hit objects   │                │
```

* **Parser** (`parser.py`): turns the indented IOS text into a tree (global lines, `interface`, `line`, `ip access-list` blocks), remembers line numbers, understands `no <command>` negation and prefix lookups (`cfg.state("ip", "http", "server")` returns *on / off / unset*), and detects the device type (router, switch or unknown) from the configuration; rules that do not apply to the type are skipped.
* **ACL model** (`acl.py`): parses standard, extended and named ACL entries into addresses, wildcard masks, protocols, ports and flags and evaluates packets against them; the policy simulator evaluates packets with this same class, so the auditor and the simulator share one definition of what an entry means.
* **Rules** (`rules/*.py`): each rule is a function decorated with `@rule(...)` carrying its identifier, severity, category, risk text, remediation text and references. The function yields `Hit` objects (what was found, the evidence lines). Adding a rule is adding one function and its tests.
* **Findings** (`model.py`, `audit.py`): a `Hit` becomes a finding with device, file, object, evidence, risk, remediation, references and status (`open` or `accepted-risk`).
* **Redaction** (`model.py`): secrets are redacted when the evidence line is created, not only when a report is written, so passwords, secrets and community strings cannot reach any output format; `tests/test_redact.py` and `tests/test_reports.py` check this with known test secrets.
* **Type 7 and MD5 handling** (`type7.py`, `md5crypt.py`): a type 7 password is decoded **only inside the process** to judge its strength (e.g. "is this `cisco`?") and is never printed. For `$1$` (type 5) hashes the salt and the hash are checked against a short list of well-known passwords; this is how a hashed default password is still caught.

## Rules

52 rules in nine categories ([full catalogue, generated](generated/rules.md)):

| Category | Examples |
|---|---|
| Access control | VTY without authentication, shared line password, console/AUX without authentication |
| Credentials | no enable secret, clear-text or reversible passwords, weak or default passwords |
| Management plane | Telnet accepted, SSH v2 not enforced, VTY not restricted to management hosts, no idle time-out, no banner, default or read-write SNMP community, HTTP server, AUX port, no AAA (an accepted risk when documented) |
| Access lists | `permit any any`, no logged deny at the end, Telnet permitted, ACL applied but undefined / defined but unused, shadowed entries |
| Layer 2 | DTP, native VLAN 1, trunk carrying every VLAN, VTP mode, no port security, no PortFast/BPDU Guard, unused ports enabled, ports or management address in VLAN 1, no DHCP snooping, no DAI |
| Services | CDP, IP source routing, legacy or unneeded services, default hostname |
| Routing | unauthenticated or plain-text-authenticated updates, RIP version 1, no `passive-interface` |
| Logging | no remote syslog server, no date/time on log messages, no NTP |
| Interfaces | proxy ARP, directed broadcasts |

Severities are the author's judgement (critical = remote access without a password; high = clear-text credentials, any-any ACLs; medium; low; info). They are meant to prioritise, not to score.

## Waivers (accepted risk)

A waiver never hides a finding. It keeps the finding in every report with status `accepted-risk` and the written reason, and it expires: after the date the finding is open again and `--fail-on` fails. A waiver without a reason, with an unknown rule or with a malformed date is an error.

```yaml
waivers:
  - rule: MGMT-009
    device: FW-EDGE
    expires: 2027-12-31
    reason: >-
      No TACACS+/RADIUS server exists in the lab. Compensating controls: ...
```

`waivers/hardened.yaml` holds the five accepted risks of the hardened design, each with its compensating controls.

## Comparing two audits

```bash
python -m ciscoaudit audit configs/baseline -f json -o baseline.json
python -m ciscoaudit audit configs/hardened --waivers waivers/hardened.yaml -f json -o hardened.json
python -m ciscoaudit compare baseline.json hardened.json --before-label baseline --after-label hardened
python -m ciscoaudit compare original.json hardened.json --map Router1=FW-EDGE --map Switch0=SW-ACCESS --map Switch1=SW-DMZ
```

Findings are matched on `(rule, device, object)`. The report counts *remediated*, *still open*, *newly introduced*, *accepted* (open → accepted-risk: the weakness is still there, now documented) and *left scope* (the device no longer exists: switching a device off removes its findings from the report, not the weakness from the network). The last two are deliberately **not** counted as remediation.

## Testing

`python -m unittest discover -s tests -t .` runs all tests (300+). Highlights:

* the rules are tested on small configuration snippets (`tests/test_rules_*.py`, 67 tests) in addition to the committed baseline and hardened configurations;
* the parser and the ACL model have their own tests (`test_parser.py`, `test_acl.py`);
* redaction tests check that no secret reaches any output format;
* `tests/test_repository_state.py` pins the committed results: the hardened configurations produce exactly the five documented accepted risks and nothing else, the baseline produces at least one critical finding and many more findings than the hardened one.
