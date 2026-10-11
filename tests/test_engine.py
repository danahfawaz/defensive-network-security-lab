"""Audit engine, waivers and rule selection."""

import tempfile
import unittest
from datetime import date
from pathlib import Path

from ciscoaudit.audit import MAX_EVIDENCE, audit_configs, audit_files, discover, select_rules
from ciscoaudit.model import Severity
from ciscoaudit.parser import ConfigError, parse_config
from ciscoaudit.rules import all_rules
from ciscoaudit.rules.base import Hit, Rule, RuleInfo
from ciscoaudit.waivers import WaiverError, load_waivers
from tests.helpers import ORIGINAL_LAB, cfg, router, switch


def fake_rule(check, rule_id="TEST-001", applies=("router", "switch"), severity=Severity.LOW):
    return Rule(RuleInfo(rule_id, "Test rule", severity, "Test", "risk", "fix", applies_to=applies), check)


class RuleSelection(unittest.TestCase):
    def test_registry_is_consistent(self):
        rules = all_rules()
        self.assertGreaterEqual(len(rules), 45)
        ids = [r.id for r in rules]
        self.assertEqual(ids, sorted(set(ids)))
        for r in rules:
            i = r.info
            for field in (i.title, i.category, i.risk, i.remediation):
                self.assertTrue(field.strip(), r.id)
            self.assertTrue(set(i.applies_to) <= {"router", "switch"}, r.id)

    def test_patterns_are_globs_and_case_insensitive(self):
        self.assertEqual([r.id for r in select_rules(["auth-*"])], ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"])
        chosen = select_rules(["L2-*"], ["L2-010", "l2-009"])
        self.assertNotIn("L2-010", [r.id for r in chosen])
        self.assertEqual(len(chosen), 8)
        self.assertEqual(len(select_rules(None, ["AUTH-*"])), len(all_rules()) - 4)

    def test_unknown_pattern_is_an_error_not_a_silent_no_op(self):
        with self.assertRaises(ValueError):
            select_rules(["NOPE-*"])
        with self.assertRaises(ValueError):
            select_rules(None, ["TYPO-1"])


class Discovery(unittest.TestCase):
    def test_directory_scan_picks_configs_sorted_and_ignores_docs(self):
        files = discover([ORIGINAL_LAB])
        self.assertEqual([f.name for f in files], [f"{n}.cfg" for n in
                         ("Router1", "Router2", "Router3", "Router4", "Switch0", "Switch1", "Switch2")])

    def test_recursive_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sub").mkdir()
            (Path(tmp) / "a.cfg").write_text("hostname A\n")
            (Path(tmp) / "sub" / "b.cfg").write_text("hostname B\n")
            (Path(tmp) / "notes.md").write_text("# not a config\n")
            self.assertEqual([f.name for f in discover([tmp])], ["a.cfg"])
            self.assertEqual([f.name for f in discover([tmp], recursive=True)], ["a.cfg", "b.cfg"])

    def test_empty_directory_and_duplicate_names_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                audit_files([tmp])
            (Path(tmp) / "x.cfg").write_text("hostname A\n")
            (Path(tmp) / "x.txt").write_text("hostname B\n")
            with self.assertRaisesRegex(ConfigError, "share the device name"):
                audit_files([tmp])


class Engine(unittest.TestCase):
    def test_findings_are_sorted_most_severe_first_then_stably(self):
        result = audit_files([ORIGINAL_LAB], strict=True)
        keys = [(-int(f.severity), f.device, f.rule_id, f.obj) for f in result.findings]
        self.assertEqual(keys, sorted(keys))

    def test_rule_applicability_by_device_type(self):
        r, s = router("hostname R\n", "r1"), switch("hostname S\n", "s1")
        result = audit_configs([r, s], rules=select_rules(["L2-010", "SVC-002"]), strict=True)
        got = sorted((f.device, f.rule_id) for f in result.findings)
        # L2-010 is switch-only, SVC-002 is router-only: each device gets exactly its own rule.
        self.assertEqual(got, [("r1", "SVC-002"), ("s1", "L2-010")])

    def test_unknown_device_type_runs_only_generic_rules_and_says_so(self):
        c = cfg("hostname Mystery\n", "mystery")
        self.assertEqual(c.device_type, "unknown")
        result = audit_configs([c], strict=True)
        ids = {f.rule_id for f in result.findings}
        self.assertNotIn("L2-010", ids)
        self.assertNotIn("SVC-002", ids)
        self.assertIn("MGMT-009", ids)
        self.assertTrue(any("device type could not be determined" in w for w in result.warnings))

    def test_a_crashing_rule_becomes_a_warning_unless_strict(self):
        def boom(_cfg):
            raise RuntimeError("kaboom")
            yield  # pragma: no cover

        ok = fake_rule(lambda c: [Hit(obj="global", detail="found")], "TEST-002")
        result = audit_configs([router("hostname R\n")], rules=[fake_rule(boom), ok])
        self.assertEqual([f.rule_id for f in result.findings], ["TEST-002"])
        self.assertTrue(any("TEST-001 failed" in w and "kaboom" in w for w in result.warnings))
        with self.assertRaises(RuntimeError):
            audit_configs([router("hostname R\n")], rules=[fake_rule(boom)], strict=True)

    def test_evidence_is_deduplicated_and_capped(self):
        c = router("hostname R\n" + "".join(f"interface FastEthernet0/{i}\n" for i in range(20)))
        lines = [i.line for i in c.interfaces]
        rule = fake_rule(lambda _c: [Hit(obj="x", detail="many", evidence=lines + lines)])
        (finding,) = audit_configs([c], rules=[rule]).findings
        self.assertEqual(len(finding.evidence), MAX_EVIDENCE)
        self.assertIn("more evidence lines omitted", finding.detail)

    def test_hit_severity_overrides_rule_default(self):
        rule = fake_rule(lambda _c: [Hit(obj="x", detail="d", severity=Severity.CRITICAL)])
        (finding,) = audit_configs([router("hostname R\n")], rules=[rule]).findings
        self.assertEqual(finding.severity, Severity.CRITICAL)


class Waivers(unittest.TestCase):
    def write(self, text: str) -> Path:
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "waivers.yaml"
        path.write_text(text)
        return path

    def test_waiver_marks_findings_accepted_but_keeps_them(self):
        path = self.write("waivers:\n  - rule: MGMT-009\n    reason: lab has no AAA server\n"
                          "  - rule: 'LOG-*'\n    device: 'Router*'\n    reason: no syslog host in the lab\n")
        result = audit_configs([router("hostname R\n", "Router1"), switch("hostname S\n", "Switch1")],
                               rules=select_rules(["MGMT-009", "LOG-001"]), waivers=load_waivers(path))
        by = {(f.device, f.rule_id): f for f in result.findings}
        self.assertTrue(by[("Router1", "MGMT-009")].waived and by[("Switch1", "MGMT-009")].waived)
        self.assertTrue(by[("Router1", "LOG-001")].waived)
        self.assertFalse(by[("Switch1", "LOG-001")].waived)  # device glob did not match
        self.assertEqual(by[("Router1", "LOG-001")].waiver_reason, "no syslog host in the lab")
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(len(result.open_findings()), 1)
        everything = result.count_by_severity(include_waived=True)
        self.assertEqual((everything["medium"], everything["low"]), (2, 2))
        open_only = result.count_by_severity()
        self.assertEqual((open_only["medium"], open_only["low"]), (1, 0))

    def test_object_glob(self):
        path = self.write("waivers:\n  - rule: MGMT-001\n    object: 'vty lines'\n    reason: documented exception\n")
        result = audit_configs([router("line vty 0 4\n", "R")], rules=select_rules(["MGMT-001"]), waivers=load_waivers(path))
        self.assertTrue(result.findings[0].waived)

    def test_expired_waiver_is_ignored_and_reported(self):
        path = self.write("waivers:\n  - rule: MGMT-009\n    reason: temporary\n    expires: 2026-01-01\n")
        result = audit_configs([router("hostname R\n")], rules=select_rules(["MGMT-009"]),
                               waivers=load_waivers(path), today=date(2026, 6, 1))
        self.assertFalse(result.findings[0].waived)
        self.assertTrue(any("expired on 2026-01-01" in w for w in result.warnings))
        result = audit_configs([router("hostname R\n")], rules=select_rules(["MGMT-009"]),
                               waivers=load_waivers(path), today=date(2025, 12, 31))
        self.assertTrue(result.findings[0].waived)

    def test_stale_waiver_is_reported(self):
        path = self.write("waivers:\n  - rule: MGMT-009\n    reason: x y z\n")
        result = audit_configs([router("aaa new-model\n")], rules=select_rules(["MGMT-009"]), waivers=load_waivers(path))
        self.assertTrue(any("matched no finding" in w for w in result.warnings))

    def test_malformed_waiver_files_are_rejected(self):
        bad_files = {
            "no reason": "waivers:\n  - rule: MGMT-009\n",
            "blank reason": "waivers:\n  - rule: MGMT-009\n    reason: '   '\n",
            "no rule": "waivers:\n  - reason: because\n",
            "typo key": "waivers:\n  - rule: MGMT-009\n    reason: ok\n    devcie: R1\n",
            "bad date": "waivers:\n  - rule: MGMT-009\n    reason: ok\n    expires: next week\n",
            "wrong shape": "- rule: MGMT-009\n",
            "not a mapping": "waivers:\n  - just a string\n",
        }
        for label, text in bad_files.items():
            with self.assertRaises(WaiverError, msg=label):
                load_waivers(self.write(text))
        self.assertEqual(load_waivers(self.write("")), [])


class Golden(unittest.TestCase):
    """Pins the Day-0 audit of the original lab; update deliberately when a rule changes."""

    def test_original_lab_day0_counts(self):
        result = audit_files([ORIGINAL_LAB], strict=True)
        self.assertEqual(len(result.devices), 7)
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.count_by_severity(), {"critical": 0, "high": 18, "medium": 59, "low": 67, "info": 0})
        high = sorted({(f.device, f.rule_id) for f in result.findings if f.severity == Severity.HIGH})
        self.assertEqual(len(high), 18)
        self.assertEqual({rule for _d, rule in high}, {"CRED-001", "MGMT-001", "RTE-001"})

    def test_original_lab_has_no_findings_that_need_credentials(self):
        # The original lab stores no passwords at all, so credential-content rules must be silent.
        result = audit_files([ORIGINAL_LAB], strict=True)
        ids = {f.rule_id for f in result.findings}
        self.assertFalse(ids & {"CRED-002", "CRED-003", "CRED-004", "AUTH-001", "MGMT-007", "MGMT-008"})


if __name__ == "__main__":
    unittest.main()
