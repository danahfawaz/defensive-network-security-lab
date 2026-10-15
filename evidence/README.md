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
| `packet-tracer/` | **observed by hand** in Packet Tracer 9.0.1 (2026-10-15) | `results.csv` (checks X-01 to X-09), `exported/` (running configurations, password hashes replaced by `XXXX`), and two reports derived from them: `export-audit.md` and `export-comparison.md` |

## How to read it honestly

* **Three kinds of evidence.** *Automated auditing* (`audit/`) and *policy simulation* (`validation/`, `policy-matrix/`) are computed from the configuration files by this repository's tools; they show that the configurations implement the written policy and are not Packet Tracer output. *Manual Packet Tracer validation* (`packet-tracer/`) is what was observed by hand: the nine checks X-01 to X-09 passed, and the manual rows of the validation reports are read from `packet-tracer/results.csv`.
* **Intended and running configuration.** `audit/02-hardened.*` audits the intended configuration files. `packet-tracer/export-audit.md` audits the running configurations exported from Packet Tracer, and `packet-tracer/export-comparison.md` lists which intended lines the running configurations do and do not contain.
* **Reproducible.** The waiver date is pinned (`2026-10-12`) and reports carry no time stamp, so `python scripts/make_evidence.py --check` reproduces the files byte for byte. A test fails if they go stale.
* **No secrets.** Reports are redacted; the configurations hold placeholder hashes only.

## Regenerate

```bash
make evidence          # rewrite everything generated in this folder (results.csv and packet-tracer/exported/ are supplied by hand)
make evidence-check    # fail if anything committed here is stale
```
