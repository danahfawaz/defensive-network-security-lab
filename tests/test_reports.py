"""Report writers, redaction guarantees, rule catalogue and report comparison."""

import csv
import io
import json
import unittest
from datetime import date

from ciscoaudit import compare as comparison
from ciscoaudit import report
from ciscoaudit.audit import audit_configs, audit_files, select_rules
from ciscoaudit.compare import ReportError, load_report
from ciscoaudit.model import Severity
from ciscoaudit.parser import load_config
from ciscoaudit.rules import all_rules
from ciscoaudit.waivers import Waiver
from tests.helpers import FIXTURES, ORIGINAL_LAB, router

SECRET_MARKERS = [
    "Sup3rSecretPw1", "hx5rVt7rPNoS4wqbXKX7m0", "0822455D0A16", "FAKEHASHVALUEFAKEHASH12",
    "Xk9-unguessable-community", "TacacsKey-Marker-77", "NtpKey-Marker-66", "OspfKey-Marker-88",
    "ConsolePw-Marker-99", "VtyPw-Marker-11",
]


def secrets_result():
    return audit_configs([load_config(FIXTURES / "secrets_router.cfg")], strict=True)


class RedactionGuarantee(unittest.TestCase):
    def test_the_fixture_really_triggers_the_credential_rules(self):
        ids = {f.rule_id for f in secrets_result().findings}
        self.assertTrue({"CRED-002", "CRED-004", "MGMT-007", "MGMT-008", "AUTH-003"} <= ids, ids)

    def test_no_secret_reaches_any_output_format(self):
        result = secrets_result()
        outputs = {
            "json": report.to_json(result),
            "markdown": report.to_markdown(result),
            "csv": report.to_csv(result),
            "text": report.to_text(result, verbose=True),
            "dict": json.dumps([f.to_dict() for f in result.findings]),
        }
        for name, text in outputs.items():
            for marker in SECRET_MARKERS:
                self.assertNotIn(marker, text, f"{marker!r} leaked into the {name} output")
        self.assertIn("<redacted>", outputs["json"])

    def test_well_known_snmp_communities_are_visible_because_they_are_the_finding(self):
        self.assertIn("snmp-server community public RO", report.to_text(secrets_result(), verbose=True))


class JsonReport(unittest.TestCase):
    def setUp(self):
        self.result = audit_files([ORIGINAL_LAB], strict=True)

    def test_structure(self):
        data = report.to_dict(self.result)
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["tool"]["name"], "ciscoaudit")
        self.assertIsNone(data["generated_at"])
        self.assertEqual(data["summary"]["devices"], 7)
        self.assertEqual(data["summary"]["findings_open"], len(data["findings"]))
        self.assertEqual(sum(data["summary"]["open_by_severity"].values()), len(data["findings"]))
        self.assertEqual([d["name"] for d in data["devices"]][:2], ["Router1", "Router2"])
        keys = {"rule_id", "title", "severity", "category", "device", "file", "object", "affected", "detail",
                "evidence", "risk", "remediation", "references", "status"}
        self.assertTrue(all(keys <= set(f) for f in data["findings"]))
        first_evidence = next(f for f in data["findings"] if f["evidence"])["evidence"][0]
        self.assertTrue({"line", "text"} <= set(first_evidence))

    def test_reports_are_reproducible_and_timestamp_is_opt_in(self):
        self.assertEqual(report.to_json(self.result), report.to_json(audit_files([ORIGINAL_LAB])))
        stamped = json.loads(report.to_json(self.result, timestamp=True))
        self.assertRegex(stamped["generated_at"], r"^\d{4}-\d\d-\d\dT")

    def test_min_severity_filter(self):
        high = report.filter_by_severity(self.result, Severity.HIGH)
        self.assertEqual({f.severity for f in high.findings}, {Severity.HIGH})
        data = json.loads(report.to_json(high, min_severity=Severity.HIGH))
        self.assertEqual(data["scope"]["min_severity"], "high")
        self.assertIs(report.filter_by_severity(self.result, None), self.result)


class OtherFormats(unittest.TestCase):
    def setUp(self):
        waiver = Waiver(rule="MGMT-009", reason="No AAA server exists in the lab", source="test")
        self.result = audit_configs([router("line vty 0 4\n login local\n", "R1")],
                                    rules=select_rules(["MGMT-001", "MGMT-009", "LOG-*"]), waivers=[waiver])

    def test_markdown_groups_by_rule_and_lists_accepted_risks(self):
        md = report.to_markdown(self.result, title="Test audit")
        self.assertTrue(md.startswith("# Test audit"))
        self.assertIn("### HIGH · MGMT-001 · Telnet is accepted for remote management", md)
        self.assertIn("**Remediation.**", md)
        self.assertIn("## Accepted risks", md)
        self.assertIn("No AAA server exists in the lab", md)
        self.assertNotIn("### LOW · MGMT-009", md)  # waived, so not listed among open findings
        self.assertIn("| **Total** |", md)

    def test_csv_round_trips(self):
        rows = list(csv.DictReader(io.StringIO(report.to_csv(self.result))))
        self.assertEqual(len(rows), len(self.result.findings))
        self.assertEqual({r["status"] for r in rows}, {"open", "accepted-risk"})
        accepted = next(r for r in rows if r["status"] == "accepted-risk")
        self.assertEqual(accepted["waiver_reason"], "No AAA server exists in the lab")

    def test_text_colour_is_opt_in(self):
        self.assertNotIn("\033[", report.to_text(self.result))
        self.assertIn("\033[", report.to_text(self.result, color=True))
        plain = report.to_text(self.result)
        self.assertIn("[accepted risk]", plain)
        self.assertNotIn("fix:", plain)
        self.assertIn("fix:", report.to_text(self.result, verbose=True))

    def test_empty_result_still_renders(self):
        empty = audit_configs([router("hostname R\n")], rules=select_rules(["AUTH-001"]))
        self.assertIn("No open findings.", report.to_markdown(empty))
        self.assertEqual(report.to_csv(empty).count("\n"), 1)


class RuleCatalogue(unittest.TestCase):
    def test_all_formats_cover_every_rule(self):
        rules = all_rules()
        self.assertEqual(len(json.loads(report.rules_to_json(rules))), len(rules))
        md, text = report.rules_to_markdown(rules), report.rules_to_text(rules)
        for r in rules:
            self.assertIn(f"## {r.id}", md)
            self.assertIn(r.id, text)


def finding(rule, device, obj="global", sev="medium", status="open", affected=(), reason=""):
    return {"rule_id": rule, "device": device, "object": obj, "severity": sev, "status": status,
            "affected": list(affected), "title": f"title {rule}", "detail": f"detail {rule}", "waiver_reason": reason}


class Compare(unittest.TestCase):
    def reports(self):
        before = {"schema_version": "1.0", "devices": [{"name": "R1"}, {"name": "S1"}], "findings": [
            finding("A-1", "R1"), finding("A-2", "R1", sev="high"),
            finding("A-3", "S1", affected=["p1", "p2", "p3"]), finding("A-4", "S1")]}
        after = {"schema_version": "1.0", "devices": [{"name": "EDGE"}, {"name": "S1"}, {"name": "EXTRA"}], "findings": [
            finding("A-2", "EDGE", sev="high"), finding("A-3", "S1", affected=["p3"]),
            finding("A-4", "S1", status="accepted-risk", reason="documented"), finding("B-1", "EXTRA")]}
        return before, after

    def test_classification_with_device_mapping(self):
        before, after = self.reports()
        diff = comparison.compare(before, after, {"R1": "EDGE"})
        s = diff["summary"]
        self.assertEqual((s["resolved"], s["persisting"], s["accepted_risk"], s["new"]), (1, 2, 1, 1))
        self.assertEqual(s["open_before"]["high"], 1)
        self.assertEqual(sum(s["open_before"].values()), 4)
        self.assertEqual(sum(s["open_after"].values()), 3)
        self.assertEqual(sum(s["accepted_after"].values()), 1)
        self.assertEqual(diff["unmatched_after"], ["EXTRA"])
        self.assertEqual(diff["unmatched_before"], [])
        shrunk = next(p for p in diff["persisting_findings"] if p["rule_id"] == "A-3")
        self.assertEqual((shrunk["affected_before"], shrunk["affected_after"]), (3, 1))
        self.assertEqual(diff["accepted_findings"][0]["reason"], "documented")
        self.assertEqual(diff["new_findings"][0]["rule_id"], "B-1")

    def test_without_mapping_renamed_devices_do_not_match(self):
        before, after = self.reports()
        diff = comparison.compare(before, after)
        self.assertEqual(diff["summary"]["resolved"], 2)  # A-1 and A-2 "disappeared" with R1
        self.assertEqual(diff["unmatched_before"], ["R1"])

    def test_waiving_is_never_counted_as_resolving(self):
        before = {"schema_version": "1.0", "devices": [{"name": "R1"}], "findings": [finding("A-1", "R1")]}
        after = {"schema_version": "1.0", "devices": [{"name": "R1"}],
                 "findings": [finding("A-1", "R1", status="accepted-risk", reason="x")]}
        s = comparison.compare(before, after)["summary"]
        self.assertEqual((s["resolved"], s["accepted_risk"]), (0, 1))

    def test_renderers(self):
        before, after = self.reports()
        diff = comparison.compare(before, after, {"R1": "EDGE"})
        md = comparison.to_markdown(diff, before_label="Day 0", after_label="Hardened")
        self.assertIn("# Remediation comparison: Day 0 → Hardened", md)
        self.assertIn("**1 resolved**", md)
        self.assertIn("| A-2 | high |", md)
        self.assertIn("open findings: 4 -> 3", comparison.to_text(diff))
        self.assertEqual(json.loads(comparison.to_json(diff))["summary"]["new"], 1)

    def test_load_report_validates(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            good.write_text(report.to_json(audit_files([ORIGINAL_LAB])))
            self.assertEqual(len(load_report(good)["devices"]), 7)
            for name, content in {"junk.json": "{not json", "other.json": '{"hello": 1}',
                                  "future.json": '{"schema_version": "2.0", "findings": []}'}.items():
                path = Path(tmp) / name
                path.write_text(content)
                with self.assertRaises(ReportError, msg=name):
                    load_report(path)
            with self.assertRaises(ReportError):
                load_report(Path(tmp) / "missing.json")


if __name__ == "__main__":
    unittest.main()
