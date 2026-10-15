#!/usr/bin/env python3
"""Regenerate the committed evidence in evidence/ from the configurations, scenarios and tests.

    python scripts/make_evidence.py          # rewrite evidence/audit, evidence/validation, evidence/policy-matrix, evidence/tests
    python scripts/make_evidence.py --check  # exit 1 if the committed evidence differs from what the tools produce now

Everything here is produced by this repository's own tools from the committed files.  The simulation, audit and matrix
reports are computed from configuration text and are not Packet Tracer output.  evidence/packet-tracer/ holds what was
observed in Packet Tracer and is supplied by hand: results.csv and exported/*.cfg (the running configurations, with every
password hash replaced by XXXX).  This script derives two reports from those exports - export-audit.md (the auditor run on
them) and export-comparison.md (which lines of the intended configuration the export does and does not contain).  The date
used for waiver expiry is pinned so that the output is identical on every run.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ciscoaudit import cli  # noqa: E402

TODAY = "2026-10-12"
MAPS = ["--map", "Router1=FW-EDGE", "--map", "Switch0=SW-ACCESS", "--map", "Switch1=SW-DMZ"]


def run(*args: str) -> str:
    """Run the CLI in-process from the repository root and return stdout; exit status 0 or 1 are both normal results."""
    out, err = io.StringIO(), io.StringIO()
    import os
    cwd = Path.cwd()
    os.chdir(ROOT)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
    finally:
        os.chdir(cwd)
    if code not in (0, 1):
        raise SystemExit(f"ciscoaudit {' '.join(args)} failed ({code}): {err.getvalue()}")
    return out.getvalue()


def audit(path: str, fmt: str, title: str, waivers: bool = False) -> str:
    extra = ["--waivers", "waivers/hardened.yaml", "--today", TODAY] if waivers else []
    return run("audit", path, "-f", fmt, "--title", title, *extra)


# --------------------------------------------------------------------------------------------------------------------
# Packet Tracer exports: which lines of the intended configuration are in the running configuration Packet Tracer holds
# --------------------------------------------------------------------------------------------------------------------

_PORT_NAMES = {"80": "www", "53": "domain", "68": "bootpc", "67": "bootps", "23": "telnet"}
_BLOCK_START = re.compile(r"^(interface |ip access-list |line |vlan |ip dhcp pool |banner )")
_STICKY_MAC = re.compile(r"mac-address sticky [0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")


def _norm(line: str) -> str:
    line = line.strip()
    line = re.sub(r"^(enable secret) \d \S+$", r"\1 <hash>", line)
    line = re.sub(r"^(username \S+ (?:privilege \d+ )?secret) \d \S+$", r"\1 <hash>", line)
    line = re.sub(r"^logging host ", "logging ", line)
    line = re.sub(r"\beq (\d+)\b", lambda m: "eq " + _PORT_NAMES.get(m.group(1), m.group(1)), line)
    return re.sub(r"\s+", " ", line)


def _blocks(text: str) -> dict[str, list[str]]:
    """Split an IOS configuration into {block header: [normalised lines]}; comments and remarks are ignored."""
    out: dict[str, list[str]] = {"(global)": []}
    current = "(global)"
    for raw in text.splitlines():
        if not raw.strip() or raw.strip() == "!" or raw.lstrip().startswith(("!", "remark")) or " remark " in raw[:12]:
            continue
        if raw.strip().startswith("remark") or raw.strip() in ("#", "^C", "no shutdown"):
            continue  # remarks, banner delimiters and 'no shutdown' (the default, which IOS does not print) carry no setting
        m = re.match(r"^interface range (\w+?)(\d+/)(\d+) - (\d+)$", raw)
        if m:  # expand 'interface range FastEthernet0/8 - 24' into the interfaces Packet Tracer lists one by one
            names = [f"interface {m.group(1)}{m.group(2)}{n}" for n in range(int(m.group(3)), int(m.group(4)) + 1)]
            for n in names:
                out.setdefault(n, [])
            current = "\0range:" + "|".join(names)
            continue
        if not raw.startswith(" "):
            if _BLOCK_START.match(raw):
                current = _norm(raw)
                out.setdefault(current, [])
            else:
                current = "(global)"
                out["(global)"].append(_norm(raw))
            continue
        line = _norm(raw)
        if current.startswith("\0range:"):
            for n in current[7:].split("|"):
                out[n].append(line)
        else:
            out[current].append(line)
    return out


def pt_export_comparison() -> str:
    exported_dir = ROOT / "evidence" / "packet-tracer" / "exported"
    devices = ["FW-EDGE", "SW-ACCESS", "SW-DMZ"]
    lines = [
        "# Intended configuration and the Packet Tracer running configuration", "",
        "Generated by `scripts/make_evidence.py` from `configs/hardened/` (what was pasted) and "
        "`evidence/packet-tracer/exported/` (`show running-config` taken in Packet Tracer, password hashes replaced by `XXXX`).", "",
        "Packet Tracer reported `% Invalid input` for some of the pasted commands; which ones was not recorded line by line, "
        "so this page does not attribute a reason. It only lists what the running configuration does and does not contain. "
        "Comments, remarks and banner delimiters are ignored; port numbers are compared by name (`80` = `www`) because Packet Tracer "
        "prints names. IOS normally does not print settings that equal their default (for example `port-security maximum 1` and "
        "`violation shutdown`), so a line missing here is not necessarily a line that was refused.", "",
    ]
    summary = []
    sections = []
    for dev in devices:
        want = _blocks((ROOT / "configs" / "hardened" / f"{dev}.cfg").read_text(encoding="utf-8"))
        have = _blocks((exported_dir / f"{dev}.cfg").read_text(encoding="utf-8"))
        missing: list[tuple[str, str]] = []
        added: list[tuple[str, str]] = []
        for header in sorted(set(want) | set(have)):
            w, h = want.get(header, []), have.get(header, [])
            for ln in w:
                if ln not in h:
                    missing.append((header, ln))
            for ln in h:
                if ln not in w and not _STICKY_MAC.search(ln):
                    added.append((header, ln))
        total = sum(len(v) for v in want.values())
        kept = total - len(missing)
        log_want = sum(1 for v in want.values() for ln in v if re.search(r"\blog$", ln))
        log_kept = sum(1 for v in have.values() for ln in v if re.search(r"\blog$", ln))
        sticky = sum(1 for v in have.values() for ln in v if _STICKY_MAC.search(ln))
        summary.append((dev, total, kept, len(missing), log_want, log_kept, sticky))
        sections.append((dev, missing, added))
    lines += ["## Summary", "", "| Device | Lines in the intended configuration | Present in the running configuration | Not present | "
              "ACL entries with `log` (intended / present) | Sticky MACs learned |", "|---|---:|---:|---:|---:|---:|"]
    for dev, total, kept, miss, lw, lk, sticky in summary:
        lines.append(f"| {dev} | {total} | {kept} | {miss} | {lw} / {lk} | {sticky} |")
    lines += [""]
    for dev, missing, added in sections:
        lines += [f"## {dev}", "", "### In the intended configuration, not in the running configuration", ""]
        if missing:
            lines += ["| Section | Line |", "|---|---|"] + [f"| `{h}` | `{ln}` |" for h, ln in missing]
        else:
            lines += ["None."]
        lines += ["", "### In the running configuration, not in the intended configuration (added or rewritten by Packet Tracer)", ""]
        if added:
            lines += ["| Section | Line |", "|---|---|"] + [f"| `{h}` | `{ln}` |" for h, ln in added]
        else:
            lines += ["None."]
        lines += [""]
    return "\n".join(lines) + "\n"


def unittest_summary() -> str:
    proc = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=ROOT,
                          capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    tail = proc.stderr.strip().splitlines()
    ran = next((line for line in tail if line.startswith("Ran ")), "")
    verdict = tail[-1] if tail else ""
    ran = re.sub(r" in [0-9.]+s", "", ran)
    return f"{ran}\n{verdict}\n"


def build(with_tests: bool) -> dict[str, str]:
    files: dict[str, str] = {}
    sets = [("00-original-lab", "configs/original-lab", "Original university lab (Day 0)", False),
            ("01-baseline", "configs/baseline", "Redesigned network, baseline configuration", False),
            ("02-hardened", "configs/hardened", "Redesigned network, hardened configuration", True)]
    for stem, path, title, waivers in sets:
        for fmt, ext in (("json", "json"), ("markdown", "md")):
            files[f"audit/{stem}.{ext}"] = audit(path, fmt, title, waivers)
    # compare() consumes the JSON reports
    with tempfile.TemporaryDirectory() as tmp:
        for stem in ("00-original-lab", "01-baseline", "02-hardened"):
            Path(tmp, f"{stem}.json").write_text(files[f"audit/{stem}.json"], encoding="utf-8")
        files["audit/compare-baseline-to-hardened.md"] = run(
            "compare", f"{tmp}/01-baseline.json", f"{tmp}/02-hardened.json", "-f", "markdown",
            "--before-label", "baseline", "--after-label", "hardened")
        files["audit/compare-original-to-hardened.md"] = run(
            "compare", f"{tmp}/00-original-lab.json", f"{tmp}/02-hardened.json", "-f", "markdown", *MAPS,
            "--before-label", "original lab", "--after-label", "hardened")
    files["validation/validation.md"] = run("validate", "--format", "markdown", "--title", "Security validation (simulation)")
    files["validation/validation.csv"] = run("validate", "--format", "csv")
    files["validation/validation.json"] = run("validate", "--format", "json")
    files["policy-matrix/matrix.md"] = run("matrix", "--format", "markdown", "--title", "Reachability matrix (simulation)")
    files["policy-matrix/matrix.csv"] = run("matrix", "--format", "csv")
    exported = ROOT / "evidence" / "packet-tracer" / "exported"
    if exported.is_dir():
        files["packet-tracer/export-audit.md"] = run(
            "audit", "evidence/packet-tracer/exported", "-f", "markdown", "--waivers", "waivers/hardened.yaml",
            "--today", TODAY, "--title", "Audit of the running configurations exported from Packet Tracer")
        files["packet-tracer/export-comparison.md"] = pt_export_comparison()
    if with_tests:
        files["tests/unittest-summary.txt"] = unittest_summary()
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if the committed evidence is stale")
    ap.add_argument("--skip-tests", action="store_true", help="do not (re)run the unit tests")
    args = ap.parse_args(argv)
    files = build(with_tests=not args.skip_tests)
    base = ROOT / "evidence"
    if args.check:
        stale = [name for name, text in files.items() if not (base / name).exists() or (base / name).read_text(encoding="utf-8") != text]
        if stale:
            print("stale evidence (run python scripts/make_evidence.py): " + ", ".join(stale), file=sys.stderr)
            return 1
        print("evidence is up to date")
        return 0
    for name, text in files.items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print("wrote", path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
