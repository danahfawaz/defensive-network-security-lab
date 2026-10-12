"""The committed configurations, waivers and topology must stay consistent with each other.

These are regression tests for the repository itself: a change to a hardened configuration that re-introduces a
weakness, an accepted-risk waiver that no longer matches anything, or a baseline that stops being insecure all fail here.
Dates are pinned so the tests do not change behaviour when a waiver's expiry date passes.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from datetime import date
from pathlib import Path

from ciscoaudit.audit import audit_files
from ciscoaudit.waivers import load_waivers

ROOT = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 12)
WAIVED = {
    ("L2-011", "SW-DMZ"),
    ("L2-012", "SW-DMZ"),
    ("MGMT-009", "FW-EDGE"),
    ("MGMT-009", "SW-ACCESS"),
    ("MGMT-009", "SW-DMZ"),
}


class HardenedConfigurations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.waivers = load_waivers(ROOT / "waivers" / "hardened.yaml")
        cls.raw = audit_files([ROOT / "configs" / "hardened"], today=TODAY)
        cls.result = audit_files([ROOT / "configs" / "hardened"], waivers=cls.waivers, today=TODAY)

    def test_only_the_documented_weaknesses_remain(self):
        self.assertEqual({(f.rule_id, f.device) for f in self.raw.findings}, WAIVED)

    def test_every_remaining_finding_is_a_written_accepted_risk(self):
        self.assertEqual(self.result.open_findings(), [])
        self.assertEqual(len(self.result.findings), len(WAIVED))
        for finding in self.result.findings:
            self.assertTrue(finding.waived)
            self.assertGreater(len(finding.waiver_reason), 60, f"{finding.rule_id} on {finding.device}: reason too thin")

    def test_no_stale_or_expired_waivers(self):
        self.assertEqual([w for w in self.result.warnings if "waiver" in w or "expired" in w], [])
        self.assertEqual(len(self.waivers), len(WAIVED))
        for waiver in self.waivers:
            self.assertIsNotNone(waiver.expires, f"{waiver.describe()} has no expiry date")
            self.assertGreater(waiver.expires, TODAY)

    def test_no_parser_warnings(self):
        self.assertEqual(self.result.warnings, [])


class BaselineConfigurations(unittest.TestCase):
    def test_the_baseline_is_meaningfully_insecure(self):
        baseline = audit_files([ROOT / "configs" / "baseline"], today=TODAY)
        hardened = audit_files([ROOT / "configs" / "hardened"], today=TODAY)
        by_severity = {s: sum(1 for f in baseline.findings if f.severity.label == s) for s in ("critical", "high")}
        self.assertGreaterEqual(by_severity["critical"], 1)
        self.assertGreaterEqual(by_severity["high"], 1)
        self.assertGreater(len(baseline.findings), 5 * len(hardened.findings))


class RepositoryScripts(unittest.TestCase):
    def run_script(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=120,
                              env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})

    def test_committed_configs_hold_placeholders_only(self):
        done = self.run_script("scripts/render_configs.py", "--check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_design_check_passes_for_both_states(self):
        done = self.run_script("-m", "ciscoaudit.cli", "design-check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("baseline: OK", done.stdout)
        self.assertIn("hardened: OK", done.stdout)


if __name__ == "__main__":
    unittest.main()
