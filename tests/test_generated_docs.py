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
            self.assertEqual(generate_docs.main(["--check"]), 1)
        finally:
            path.write_text(original, encoding="utf-8")
        self.assertEqual(generate_docs.main(["--check"]), 0)


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
