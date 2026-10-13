# Evidence

What is committed here, how it was produced, and what it is **not**.

| Folder | Produced by | What it shows |
|---|---|---|
| `audit/00-original-lab.*` | `ciscoaudit audit configs/original-lab` | The university lab as submitted (7 devices, "Day 0"): the starting point |
| `audit/01-baseline.*` | `ciscoaudit audit configs/baseline` | The redesigned network configured the way a first working version usually is |
| `audit/02-hardened.*` | `ciscoaudit audit configs/hardened --waivers waivers/hardened.yaml` | The remediated configuration; accepted risks are listed with their reason |
| `audit/compare-*.md` | `ciscoaudit compare` | What the remediation changed (findings of devices that no longer exist are *not* counted as fixed) |
| `validation/` | `ciscoaudit validate` | 124 scenarios: business flows that must work, attacks that must fail, layer-2 and hygiene checks, documented limitations |
| `policy-matrix/` | `ciscoaudit matrix` | Every sender × destination × service against the written policy |
| `tests/unittest-summary.txt` | `python -m unittest discover` | Snapshot of the unit-test result when the evidence was generated |
| `packet-tracer/` | **you**, by running [the test plan](../docs/pt-test-plan.md) | Empty results sheet. Nothing here has been run in Packet Tracer yet |

## How to read it honestly

* **Simulated, not observed.** The validation and matrix results are computed from the configuration files by this repository's policy simulator. They show that the configurations implement the written policy; they are not Packet Tracer output. Packet Tracer results are *pending* in every report.
* **Intended configuration.** The audit of `configs/hardened` is an audit of the intended configuration files, not of a device exported from Packet Tracer.
* **Reproducible.** The waiver date is pinned (`2026-10-12`) and reports carry no time stamp, so `python scripts/make_evidence.py --check` reproduces the files byte for byte. A test fails if they go stale.
* **No secrets.** Reports are redacted; the configurations hold placeholder hashes only.

## Regenerate

```bash
make evidence          # rewrite everything in this folder except packet-tracer/
make evidence-check    # fail if anything committed here is stale
```
