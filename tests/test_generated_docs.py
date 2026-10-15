"""The committed tables and diagram source in docs/generated/ must match topology/topology.yaml."""

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

from ciscoaudit import cli

from tests.helpers import ROOT

_spec = importlib.util.spec_from_file_location("generate_docs", ROOT / "scripts" / "generate_docs.py")
generate_docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_docs)


class GeneratedDocs(unittest.TestCase):
    def test_committed_files_are_up_to_date(self):
        for path, text in generate_docs.render().items():
            self.assertTrue(path.exists(), f"{path} missing - run python scripts/generate_docs.py")
            self.assertEqual(path.read_text(encoding="utf-8"), text, f"{path} is stale - run python scripts/generate_docs.py")

    def test_every_host_and_link_is_documented(self):
        topo = generate_docs.load()
        addressing = (ROOT / "docs/generated/addressing.md").read_text(encoding="utf-8")
        cabling = (ROOT / "docs/generated/cabling.md").read_text(encoding="utf-8")
        for host, data in topo["hosts"].items():
            self.assertIn(f"| {host} |", addressing)
            self.assertIn(data["ip"], addressing)
        for link in topo["links"]:
            self.assertIn(f"| {link['a']} | {link['b']} |", cabling)

    def test_check_flag_detects_a_stale_file(self):
        path = ROOT / "docs/generated/addressing.md"
        original = path.read_text(encoding="utf-8")
        try:
            path.write_text(original + "\nedited\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(generate_docs.main(["--check"]), 1)
        finally:
            path.write_text(original, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(generate_docs.main(["--check"]), 0)


class ThreatModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import re
        import yaml
        text = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
        cls.defined = set(re.findall(r"^\| (T\d\d) \|", text, re.M))
        cls.scenarios = yaml.safe_load((ROOT / "scenarios/scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]

    def test_twelve_threats_are_defined(self):
        self.assertEqual(self.defined, {f"T{i:02d}" for i in range(1, 13)})

    def test_scenarios_only_reference_defined_threats(self):
        used = {t for sc in self.scenarios for t in sc.get("threats", [])}
        self.assertLessEqual(used, self.defined)

    def test_every_threat_has_a_simulated_scenario(self):
        for tid in sorted(self.defined):
            simulated = [sc["id"] for sc in self.scenarios if tid in sc.get("threats", []) and sc["category"] != "manual"]
            self.assertTrue(simulated, f"{tid} has no simulated scenario")


class QuotedNumbers(unittest.TestCase):
    """docs/validation.md quotes results; they must be the ones the tools produce."""

    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "docs/validation.md").read_text(encoding="utf-8").replace("\u00a0", " ")

    def test_matrix_figures(self):
        from ciscoaudit.policy import matrix as mx
        from ciscoaudit.policy.topology import load_topology
        topology = load_topology(ROOT / "topology/topology.yaml")
        intent = mx.load_intent(ROOT / "topology/policy-intent.yaml", topology)
        base, hard = (mx.summary(mx.compute(topology, st, intent)) for st in ("baseline", "hardened"))
        def spaced(n):
            return f"{n:,}".replace(",", " ")
        self.assertIn(f"{spaced(hard['probes'])} probes", self.text)
        self.assertIn(f"{spaced(base['permitted_between_zones'])} probes cross zones against {hard['permitted_between_zones']} hardened", self.text)
        self.assertIn(f"({hard['permitted_inside_a_zone']} of the {hard['permitted']} permitted hardened probes)", self.text)
        self.assertEqual((hard["unexpected_permits"], hard["unexpected_blocks"]), (0, 0))

    def test_scenario_figures(self):
        import json
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["validate", "--topology", str(ROOT / "topology/topology.yaml"), "--scenarios", str(ROOT / "scenarios/scenarios.yaml"),
                      "--format", "json"])
        data = json.loads(out.getvalue())
        self.assertIn(f"{len(data['scenarios'])} scenarios", self.text)
        hard, base = data["summary"]["hardened"], data["summary"]["baseline"]
        self.assertIn(f"{hard['pass']} passed, {hard['fail']} failed**", self.text)
        self.assertIn(f"{hard['observed']} manual checks observed in Packet Tracer", self.text)
        self.assertEqual(hard["pending"], 0, "wording about pending Packet Tracer checks was removed from the docs")
        self.assertIn(f"{base['pass']} asserted pass, {base['info']} informational", self.text)


class ReadmeNumbers(unittest.TestCase):
    """The headline numbers in README.md must be the ones the tools produce."""

    def audit_summary(self, path: str, waivers: bool) -> dict:
        import json
        args = ["audit", str(ROOT / path), "-f", "json"]
        if waivers:
            args += ["--waivers", str(ROOT / "waivers/hardened.yaml"), "--today", "2026-10-12"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cli.main(args)
        return json.loads(out.getvalue())["summary"]

    def test_audit_table(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for label, path, waivers in (("Original university lab (7 devices) ¹", "configs/original-lab", False),
                                     ("Redesigned network, **baseline** configuration", "configs/baseline", False),
                                     ("Redesigned network, **hardened** configuration", "configs/hardened", True)):
            sm = self.audit_summary(path, waivers)
            sev = sm["open_by_severity"]
            open_ = f"**{sm['findings_open']}**" if waivers else str(sm["findings_open"])
            accepted = f"{sm['findings_accepted_risk']} (documented, expiring)" if waivers else str(sm["findings_accepted_risk"])
            row = f"| {label} | {open_} | {sev['critical']} | {sev['high']} | {sev['medium']} | {sev['low']} | {accepted} |"
            self.assertIn(row, text)

    def test_matrix_sentence(self):
        from ciscoaudit.policy import matrix as mx
        from ciscoaudit.policy.topology import load_topology
        topology = load_topology(ROOT / "topology/topology.yaml")
        intent = mx.load_intent(ROOT / "topology/policy-intent.yaml", topology)
        base, hard = (mx.summary(mx.compute(topology, st, intent)) for st in ("baseline", "hardened"))
        text = (ROOT / "README.md").read_text(encoding="utf-8").replace("\u00a0", " ")
        probes = f"{hard['probes']:,}".replace(",", " ")
        crossing = f"{base['permitted_between_zones']:,}".replace(",", " ")
        self.assertIn(f"{hard['unexpected_permits'] + hard['unexpected_blocks']} of {probes}", text)
        self.assertIn(f"the baseline lets {crossing} probes cross zones; the hardened network {hard['permitted_between_zones']}", text)


class Evidence(unittest.TestCase):
    def test_committed_evidence_is_up_to_date(self):
        spec = importlib.util.spec_from_file_location("make_evidence", ROOT / "scripts" / "make_evidence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        files = module.build(with_tests=False)
        for name, text in files.items():
            path = ROOT / "evidence" / name
            self.assertTrue(path.exists(), f"{path} missing - run make evidence")
            self.assertEqual(path.read_text(encoding="utf-8"), text, f"evidence/{name} is stale - run make evidence")

    def test_generator_never_writes_what_was_observed_in_packet_tracer(self):
        """results.csv and the exported running configurations are supplied by hand; only reports derived from them are generated."""
        spec = importlib.util.spec_from_file_location("make_evidence2", ROOT / "scripts" / "make_evidence.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        written = {n for n in module.build(with_tests=False) if n.startswith("packet-tracer")}
        self.assertEqual(written, {"packet-tracer/export-audit.md", "packet-tracer/export-comparison.md"})


class PacketTracerExports(unittest.TestCase):
    """The running configurations exported from Packet Tracer are public: they must carry no password material."""

    devices = ("FW-EDGE", "SW-ACCESS", "SW-DMZ")

    def test_exports_exist_for_every_audited_device(self):
        for dev in self.devices:
            self.assertTrue((ROOT / "evidence/packet-tracer/exported" / f"{dev}.cfg").is_file(), dev)

    def test_exports_hold_redacted_secrets_only(self):
        import re
        for dev in self.devices:
            text = (ROOT / "evidence/packet-tracer/exported" / f"{dev}.cfg").read_text(encoding="utf-8")
            self.assertNotIn("$1$", text, dev)
            self.assertNotIn("\r", text, dev)
            secrets = re.findall(r"^.*\b(?:secret|password) \d? ?(\S+)$", text, flags=re.M)
            self.assertTrue(secrets, dev)
            for value in secrets:
                self.assertIn(value, ("XXXX", "password-encryption"), f"{dev}: unredacted value on a secret/password line")

    def test_every_recorded_result_has_a_date(self):
        import csv
        with (ROOT / "evidence/packet-tracer/results.csv").open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row["packet_tracer_result"] not in ("", "not-run"):
                    self.assertTrue(row["date"], row["id"])


class PacketTracerPlan(unittest.TestCase):
    def test_committed_test_plan_matches_the_scenarios(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp, "plan.md")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["validate", "--topology", str(ROOT / "topology/topology.yaml"), "--scenarios", str(ROOT / "scenarios/scenarios.yaml"),
                          "--state", "hardened", "--pt-plan", str(plan)])
            self.assertEqual((ROOT / "docs/pt-test-plan.md").read_text(encoding="utf-8"), plan.read_text(encoding="utf-8"),
                             "docs/pt-test-plan.md is stale - regenerate it (see docs/packet-tracer-build.md, step 6)")


if __name__ == "__main__":
    unittest.main()
