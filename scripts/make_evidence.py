#!/usr/bin/env python3
"""Regenerate the committed evidence in evidence/ from the configurations, scenarios and tests.

    python scripts/make_evidence.py          # rewrite evidence/audit, evidence/validation, evidence/policy-matrix, evidence/tests
    python scripts/make_evidence.py --check  # exit 1 if the committed evidence differs from what the tools produce now

Everything here is produced by this repository's own tools from the committed files.  None of it is Packet Tracer output
(evidence/packet-tracer/ is reserved for that and is never touched by this script).  The date used for waiver expiry is
pinned so that the output is identical on every run.
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
