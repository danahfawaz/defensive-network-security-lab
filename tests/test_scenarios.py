"""Scenario files, the validation run, its reports, and the `validate` / `trace` / `pt-compare` commands."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

from ciscoaudit import cli
from ciscoaudit.policy import scenarios as sc, validation_report as vr
from ciscoaudit.policy.topology import load_topology
from tests.helpers import ROOT, Workspace

SCENARIOS = ROOT / "scenarios" / "scenarios.yaml"
TOPOLOGY = ROOT / "topology" / "topology.yaml"


def write(tmp: Path, text: str) -> Path:
    path = tmp / "s.yaml"
    path.write_text(textwrap.dedent(text))
    return path


class CommittedScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = load_topology(TOPOLOGY)
        cls.scenarios = sc.load_scenarios(SCENARIOS, cls.topology)
        cls.validation = sc.run_scenarios(cls.topology, cls.scenarios)

    def test_catalogue_is_broad_enough_to_mean_something(self):
        by_category: dict[str, int] = {}
        for s in self.scenarios:
            by_category[s.category] = by_category.get(s.category, 0) + 1
        self.assertEqual(set(by_category), set(sc.CATEGORIES), "every category is used")
        self.assertGreaterEqual(by_category["permitted"], 25)
        self.assertGreaterEqual(by_category["blocked"], 30)
        self.assertGreaterEqual(by_category["spoofing"], 8)
        self.assertGreaterEqual(by_category["management"], 12)
        self.assertEqual(len({s.id for s in self.scenarios}), len(self.scenarios))

    def test_hardened_configurations_meet_every_expectation(self):
        self.assertEqual([(r.scenario.id, o.detail) for r, o in self.validation.failures], [])
        self.assertEqual(self.validation.count("hardened", "fail"), 0)
        self.assertEqual(self.validation.count("hardened", "info"), 0, "every scenario states what the hardened network must do")
        self.assertEqual(self.validation.count("hardened", "pending"), sum(1 for s in self.scenarios if s.kind == "manual"))

    def test_baseline_results_are_asserted_not_assumed(self):
        asserted = [s for s in self.scenarios if s.kind != "manual" and s.baseline]
        self.assertGreater(len(asserted), 80)
        self.assertEqual(self.validation.count("baseline", "pass"), len(asserted))
        self.assertEqual(self.validation.count("baseline", "fail"), 0)

    def test_attack_scenarios_succeed_against_the_baseline_except_where_documented(self):
        documented = {
            "B-02": "the baseline already isolated Guest from Users",
            "B-26": "blocked by the discard route, which exists in both states",
            "B-27": "the simulated ISP has no route to private addresses in both states",
            "B-28": "the simulated ISP has no route to private addresses in both states",
            "B-13": "the baseline stops the reply, so only the request is meaningful; no baseline result is asserted",
            "M-01": "SSH to a baseline device cannot be asserted: the RSA key is not part of an exported configuration",
            "M-07": "same reason as M-01",
            "M-10": "same reason as M-01",
            "M-15": "same reason as M-01",
            "M-16": "same reason as M-01",
        }
        found = {s.id for s in self.scenarios
                 if s.category in ("blocked", "spoofing", "management") and s.kind == "flow" and s.baseline != "delivered"}
        self.assertEqual(found, set(documented), "a new attack scenario must show the baseline is vulnerable, or be listed here with a reason")

    def test_blocked_scenarios_name_what_stops_them(self):
        for s in self.scenarios:
            if s.kind == "flow" and s.expect == "blocked":
                self.assertTrue(s.by and s.at, f"{s.id} should say which control stops it, and where")

    def test_design_checks_pass_in_the_run(self):
        self.assertEqual(self.validation.design_ok, {"baseline": True, "hardened": True})


class Loader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.topology = load_topology(TOPOLOGY)

    def rejects(self, body: str, fragment: str) -> None:
        text = "schema: 1\nscenarios:\n" + textwrap.indent(textwrap.dedent(body).strip("\n"), "  ") + "\n"
        path = self.tmp / "s.yaml"
        path.write_text(text)
        with self.assertRaises(sc.ScenarioError) as ctx:
            sc.load_scenarios(path, self.topology)
        self.assertIn(fragment, str(ctx.exception))

    def test_file_level_problems(self):
        path = self.tmp / "s.yaml"
        path.write_text("scenarios: []\n")
        with self.assertRaises(sc.ScenarioError):
            sc.load_scenarios(path)
        path.write_text(": : :")
        with self.assertRaises(sc.ScenarioError):
            sc.load_scenarios(path)
        with self.assertRaises(sc.ScenarioError):
            sc.load_scenarios(self.tmp / "missing.yaml")

    def test_duplicate_ids_and_unknown_keys(self):
        ok = '- {id: A, title: t, category: permitted, flow: "PC0 -> SRV-APP tcp/80", expect: delivered}\n'
        self.rejects(ok + ok, "duplicate id A")
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC0 -> SRV-APP tcp/80", expect: delivered, colour: red}', "unknown key")

    def test_flow_must_be_understood_and_name_known_nodes(self):
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC0 SRV-APP tcp/80", expect: delivered}', "cannot read flow")
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC9 -> SRV-APP tcp/80", expect: delivered}', "PC9")
        self.rejects('- {id: A, title: t, category: permitted, flow: "ISP-R -> SRV-APP tcp/80", expect: delivered}', "test infrastructure")

    def test_expectations_are_checked(self):
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC0 -> SRV-APP tcp/80", expect: maybe}', "expect must be one of")
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC0 -> SRV-APP tcp/80", expect: delivered, baseline: clean}', "baseline must be")
        self.rejects('- {id: A, title: t, category: permitted, flow: "PC0 -> SRV-APP tcp/80", expect: delivered, by: IN-USERS}', "only make sense")
        self.rejects('- {id: A, title: t, category: blocked, flow: "PC0 -> SRV-APP tcp/80", expect: blocked, phase: later}', "phase must be")
        self.rejects('- {id: A, title: t, category: nonsense, flow: "PC0 -> SRV-APP tcp/80", expect: delivered}', "category must be")

    def test_limitations_must_say_which_limitation(self):
        self.rejects('- {id: A, title: t, category: limitation, flow: "PC0 -> PC1 tcp/445", expect: delivered}', "which limitation")

    def test_audit_and_manual_scenarios(self):
        self.rejects("- {id: A, title: t, category: layer2, kind: audit, expect: clean}", "check:")
        self.rejects("- {id: A, title: t, category: layer2, kind: audit, check: {rules: [NOPE-1]}, expect: clean}", "matches no rule")
        self.rejects("- {id: A, title: t, category: layer2, kind: audit, check: {rules: [L2-001]}, expect: delivered}", "expect must be one of")
        self.rejects("- {id: A, title: t, category: manual, kind: manual}", "needs 'steps'")


class Mutations(unittest.TestCase):
    """The validator must fail when a control is removed, and name the scenarios that notice."""

    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def failing_ids(self, state: str = "hardened") -> set[str]:
        topology = load_topology(self.ws.topology_path)
        run = sc.run_scenarios(topology, sc.load_scenarios(SCENARIOS, topology), (state,))
        return {r.scenario.id for r, _ in run.failures}

    def test_clean_copy_has_no_failures(self):
        self.assertEqual(self.failing_ids(), set())

    def test_removing_the_outside_anti_spoofing_entries_is_caught(self):
        self.ws.edit("hardened", "FW-EDGE", " deny ip 10.0.0.0 0.255.255.255 any log\n", " remark removed\n")
        self.assertEqual(self.failing_ids(), {"S-01"})

    def test_opening_the_outside_acl_is_caught_by_many_scenarios(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-list extended IN-OUTSIDE\n", "ip access-list extended IN-OUTSIDE\n permit ip any any\n")
        failing = self.failing_ids()
        self.assertTrue({"B-20", "B-21", "B-22", "B-23", "B-24", "B-25", "B-26", "S-01", "S-05"} <= failing, failing)

    def test_breaking_a_reply_rule_is_caught_by_the_business_scenario(self):
        self.ws.edit("hardened", "FW-EDGE", " permit tcp host 10.10.20.10 eq 443 10.10.10.0 0.0.0.255 established\n", "")
        self.assertIn("P-01", self.failing_ids())

    def test_removing_the_vty_restriction_is_caught(self):
        self.ws.edit("hardened", "SW-ACCESS", " access-class VTY-ADMIN in\n", "", count=2)
        self.assertTrue({"M-01"} <= self.failing_ids())

    def test_a_config_regression_is_caught_by_the_audit_scenarios(self):
        self.ws.edit("hardened", "SW-ACCESS", " switchport port-security\n", "", count=50)
        self.assertIn("L-03", self.failing_ids())

    def test_fixing_a_documented_limitation_makes_its_scenario_fail(self):
        # K-04 documents that hairpin traffic is dropped; if someone fixes that, the documentation must be updated
        self.ws.edit("hardened", "FW-EDGE", "ip route 203.0.113.8 255.255.255.248 Null0\n", "")
        self.assertIn("K-04", self.failing_ids())

    def test_the_baseline_assertions_fail_if_the_baseline_gets_secured(self):
        self.ws.edit("baseline", "FW-EDGE", "access-list 101 permit ip any any\n", "access-list 101 deny ip any any\n")
        self.assertIn("B-01", self.failing_ids("baseline"))


class Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = load_topology(TOPOLOGY)
        cls.validation = sc.run_scenarios(cls.topology, sc.load_scenarios(SCENARIOS, cls.topology))

    def test_json_is_complete_and_honest_about_its_origin(self):
        data = json.loads(vr.to_json(self.validation))
        self.assertEqual(data["summary"]["hardened"]["fail"], 0)
        self.assertIn("not Packet Tracer results", data["note"])
        flow = next(s for s in data["scenarios"] if s["id"] == "B-22")
        self.assertEqual(flow["results"]["hardened"]["blocked_by"], "IN-OUTSIDE")
        self.assertTrue(flow["results"]["hardened"]["request_trace"])
        self.assertEqual(flow["results"]["baseline"]["actual"], "delivered")

    def test_csv_has_one_row_per_scenario(self):
        rows = list(csv.DictReader(io.StringIO(vr.to_csv(self.validation))))
        self.assertEqual(len(rows), len(self.validation.results))
        row = next(r for r in rows if r["id"] == "B-22")
        self.assertEqual((row["baseline_actual"], row["hardened_actual"], row["hardened_stopped_by"]), ("delivered", "blocked", "IN-OUTSIDE"))

    def test_markdown_carries_the_disclaimer_and_a_summary(self):
        text = vr.to_markdown(self.validation)
        self.assertIn("**not** Packet Tracer results", text)
        self.assertIn("| Scenarios that failed | 0 | 0 |", text)
        self.assertIn("Traffic that must be stopped", text)

    def test_text_report_lists_failures_with_their_reason(self):
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("hardened", "FW-EDGE", " deny ip 10.0.0.0 0.255.255.255 any log\n", " remark removed\n")
        topology = load_topology(ws.topology_path)
        run = sc.run_scenarios(topology, sc.load_scenarios(SCENARIOS, topology), ("hardened",))
        text = vr.to_text(run, verbose=True)
        self.assertIn("1 FAILURE(S)", text)
        self.assertIn("S-01", text)
        self.assertIn("expected blocked but the simulator says delivered", text)

    def test_packet_tracer_plan_separates_what_a_pc_can_and_cannot_send(self):
        plan = vr.pt_plan_markdown(self.validation, self.topology)
        self.assertIn("ssh -l admin 10.10.99.1", plan)
        self.assertIn("Web Browser", plan)
        self.assertIn("Verified by simulation only", plan)
        self.assertIn("no stock PC tool is known to forge a source address (not verified)", plan)
        rows = {r["id"]: r for r in vr.pt_plan_rows(self.validation, self.topology)}
        self.assertFalse(rows["S-01"]["testable"])
        self.assertFalse(rows["K-01"]["testable"])
        self.assertTrue(rows["B-22"]["testable"])
        self.assertEqual(rows["B-22"]["predicted"], "fails / no answer")

    def test_results_template_starts_with_nothing_run(self):
        rows = list(csv.DictReader(io.StringIO(vr.pt_results_template(self.validation, self.topology))))
        self.assertTrue(rows)
        self.assertEqual({r["packet_tracer_result"] for r in rows}, {"not-run"})
        self.assertNotIn("S-01", {r["id"] for r in rows})

    def test_comparison_with_recorded_results(self):
        sheet = "id,simulator_predicts,packet_tracer_result\nP-01,succeeds,succeeded\nB-22,blocked,succeeded\nB-20,blocked,blocked\nP-02,succeeds,not-run\nP-03,succeeds,not-supported\nZZ-9,x,blocked\n"
        out = vr.pt_compare(self.validation, sheet)
        self.assertEqual(out["agree"], ["P-01", "B-20"])
        self.assertEqual(out["disagree"], [{"id": "B-22", "simulator": "blocked", "packet_tracer": "succeeded"}])
        self.assertEqual((out["not_run"], out["not_supported"], out["unknown_ids"]), (["P-02"], ["P-03"], ["ZZ-9"]))


class Commands(unittest.TestCase):
    def call(self, *args: str) -> tuple[int, str]:
        import contextlib

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(list(args))
        return code, out.getvalue()

    def setUp(self):
        self._cwd = Path.cwd()
        import os

        os.chdir(ROOT)
        self.addCleanup(os.chdir, self._cwd)

    def test_validate_passes_on_the_committed_lab(self):
        code, out = self.call("validate", "--state", "hardened")
        self.assertEqual(code, 0, out)
        self.assertIn("hardened: 115 passed, 0 failed", out)

    def test_validate_filters_and_formats(self):
        code, out = self.call("validate", "--only", "B-2*", "-f", "csv")
        self.assertEqual(code, 0)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(out)))), 10)  # B-20 .. B-29
        with tempfile.TemporaryDirectory() as tmp:
            plan, sheet = Path(tmp, "plan.md"), Path(tmp, "r.csv")
            code, _ = self.call("validate", "--only", "P-*", "--pt-plan", str(plan), "--pt-results-template", str(sheet))
            self.assertEqual(code, 0)
            self.assertIn("Packet Tracer test plan", plan.read_text())
            self.assertTrue(sheet.read_text().startswith("id,simulator_predicts"))

    def test_validate_exits_1_when_a_scenario_fails_and_2_on_bad_input(self):
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("hardened", "FW-EDGE", " deny ip 10.0.0.0 0.255.255.255 any log\n", " remark removed\n")
        code, out = self.call("validate", "--topology", str(ws.topology_path), "--scenarios", str(SCENARIOS), "--state", "hardened")
        self.assertEqual(code, 1)
        self.assertIn("S-01", out)
        self.assertEqual(self.call("validate", "--only", "NOPE-*")[0], 2)
        self.assertEqual(self.call("validate", "--scenarios", "no-such-file.yaml")[0], 2)

    def test_trace_prints_both_states(self):
        code, out = self.call("trace", "PC5 -> 203.0.113.2 tcp/23", "--state", "both")
        self.assertEqual(code, 0)
        self.assertIn("[baseline]", out)
        self.assertIn("[hardened]", out)
        self.assertIn("denied at FW-EDGE", out)
        self.assertEqual(self.call("trace", "garbage")[0], 2)

    def test_pt_compare_reports_disagreement_with_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp, "good.csv")
            good.write_text("id,packet_tracer_result\nP-01,succeeded\nB-22,blocked\n")
            code, out = self.call("pt-compare", str(good))
            self.assertEqual(code, 0)
            self.assertIn("agree with the simulator: 2", out)
            bad = Path(tmp, "bad.csv")
            bad.write_text("id,packet_tracer_result\nB-22,succeeded\n")
            code, out = self.call("pt-compare", str(bad))
            self.assertEqual(code, 1)
            self.assertIn("DISAGREE B-22", out)
        self.assertEqual(self.call("pt-compare", "missing.csv")[0], 2)

    def test_scenario_file_is_valid_yaml_with_the_documented_header(self):
        data = yaml.safe_load(SCENARIOS.read_text())
        self.assertEqual(data["schema"], 1)


if __name__ == "__main__":
    unittest.main()
