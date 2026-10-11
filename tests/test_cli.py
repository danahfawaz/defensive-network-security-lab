"""End-to-end tests of the command-line interface."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciscoaudit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests.helpers import ORIGINAL_LAB, ROOT


def run_cli(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse exits on usage errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class AuditCommand(unittest.TestCase):
    def test_text_report_and_exit_codes(self):
        code, out, _ = run_cli("audit", str(ORIGINAL_LAB))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("7 device(s), 50 rules", out)
        self.assertIn("open: 0 critical, 18 high, 59 medium, 67 low, 0 info", out)

    def test_fail_on_threshold(self):
        self.assertEqual(run_cli("audit", str(ORIGINAL_LAB), "--fail-on", "high")[0], EXIT_FINDINGS)
        self.assertEqual(run_cli("audit", str(ORIGINAL_LAB), "--fail-on", "critical")[0], EXIT_OK)

    def test_json_output_and_filters(self):
        code, out, _ = run_cli("audit", str(ORIGINAL_LAB), "-f", "json", "--rules", "AUTH-*,MGMT-001",
                               "--exclude-rules", "AUTH-004", "--min-severity", "medium")
        self.assertEqual(code, EXIT_OK)
        data = json.loads(out)
        self.assertEqual(data["scope"]["min_severity"], "medium")
        self.assertEqual({f["rule_id"] for f in data["findings"]}, {"AUTH-002", "MGMT-001"})
        self.assertNotIn("AUTH-004", data["scope"]["rules_run"])

    def test_output_file_and_other_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fmt, needle in (("markdown", "# Cisco configuration security audit"), ("csv", "severity,rule_id"),
                                ("json", '"schema_version"')):
                target = Path(tmp) / "sub" / f"report.{fmt}"
                code, out, err = run_cli("audit", str(ORIGINAL_LAB), "-f", fmt, "-o", str(target))
                self.assertEqual((code, out), (EXIT_OK, ""))
                self.assertIn("wrote", err)
                self.assertIn(needle, target.read_text())

    def test_errors_exit_2_with_a_message(self):
        for argv in (["audit", "/no/such/file.cfg"], ["audit", str(ORIGINAL_LAB), "--rules", "NOPE-1"],
                     ["audit", str(ORIGINAL_LAB), "--waivers", "/no/such/waivers.yaml"]):
            code, _out, err = run_cli(*argv)
            self.assertEqual(code, EXIT_ERROR, argv)
            self.assertIn("ciscoaudit: error:", err)
        self.assertEqual(run_cli("audit", str(ORIGINAL_LAB), "--min-severity", "extreme")[0], 2)
        self.assertEqual(run_cli()[0], 2)

    def test_waivers_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.yaml"
            path.write_text("waivers:\n  - rule: MGMT-009\n    reason: no AAA server in the lab\n")
            code, out, _ = run_cli("audit", str(ORIGINAL_LAB), "-f", "json", "--rules", "MGMT-009", "--waivers", str(path))
            data = json.loads(out)
            self.assertEqual(data["summary"]["findings_open"], 0)
            self.assertEqual(data["summary"]["findings_accepted_risk"], 7)
            self.assertEqual(run_cli("audit", str(ORIGINAL_LAB), "--rules", "MGMT-009", "--waivers", str(path),
                                     "--fail-on", "low")[0], EXIT_OK)  # accepted risk does not fail the gate


class CompareAndRules(unittest.TestCase):
    def test_compare_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.json"
            after_cfg = Path(tmp) / "edge.cfg"
            after = Path(tmp) / "after.json"
            run_cli("audit", str(ORIGINAL_LAB / "Router2.cfg"), "-f", "json", "-o", str(before))
            after_cfg.write_text((ORIGINAL_LAB / "Router2.cfg").read_text().replace("hostname Router", "hostname EDGE")
                                 + "\nenable secret 5 $1$abcd$abcdefghijklmnopqrstuv\n")
            run_cli("audit", str(after_cfg), "-f", "json", "-o", str(after))
            code, out, _ = run_cli("compare", str(before), str(after), "--map", "Router2=edge", "-f", "json")
            self.assertEqual(code, EXIT_OK)
            diff = json.loads(out)
            self.assertEqual(diff["summary"]["resolved"], 1)  # only CRED-001 changed
            self.assertEqual(diff["summary"]["new"], 0)
            self.assertEqual(run_cli("compare", str(before), str(after), "--map", "oops")[0], EXIT_ERROR)
            self.assertEqual(run_cli("compare", str(before), "/missing.json")[0], EXIT_ERROR)

    def test_rules_command(self):
        code, out, _ = run_cli("rules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("MGMT-001", out)
        code, out, _ = run_cli("rules", "-f", "json", "--category", "layer 2")
        self.assertEqual({r["id"] for r in json.loads(out)}, {f"L2-{n:03d}" for n in range(1, 11)})
        self.assertEqual(run_cli("rules", "--category", "nonsense")[0], EXIT_ERROR)

    def test_python_dash_m_entry_point(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        proc = subprocess.run([sys.executable, "-m", "ciscoaudit", "--version"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(proc.stdout.startswith("ciscoaudit "))


if __name__ == "__main__":
    unittest.main()
