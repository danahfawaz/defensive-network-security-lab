"""The exhaustive reachability matrix and the written policy it is checked against."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from ciscoaudit import cli
from ciscoaudit.policy import matrix as mx
from ciscoaudit.policy.topology import load_topology
from tests.helpers import ROOT, Workspace

TOPOLOGY = ROOT / "topology" / "topology.yaml"
INTENT = ROOT / "topology" / "policy-intent.yaml"


def compute(state: str, topology_path: Path = TOPOLOGY, intent_path: Path = INTENT) -> mx.Matrix:
    topology = load_topology(topology_path)
    return mx.compute(topology, state, mx.load_intent(intent_path, topology))


def kinds(matrix: mx.Matrix) -> set[tuple[str, str, str, str]]:
    return {(c.violation or "", c.sender, c.destination, c.service) for c in matrix.violations}


class RealLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hardened = compute("hardened")
        cls.baseline = compute("baseline")

    def test_hardened_configuration_permits_exactly_what_the_policy_lists(self):
        self.assertEqual(kinds(self.hardened), set())

    def test_every_probe_is_accounted_for(self):
        m = self.hardened
        pairs = sum(len(m.destinations) - (1 if sender in m.destinations else 0) for sender in m.senders)
        self.assertEqual(len(m.cells), pairs * len(m.services))

    def test_baseline_is_open_but_not_broken(self):
        s = mx.summary(self.baseline)
        self.assertEqual(s["unexpected_blocks"], 0, "the baseline is a working network")
        self.assertGreater(s["unexpected_permits"], 1000)

    def test_hardening_shrinks_what_crosses_zones_by_an_order_of_magnitude(self):
        before, after = mx.summary(self.baseline), mx.summary(self.hardened)
        self.assertGreater(before["permitted_between_zones"], 10 * after["permitted_between_zones"])

    def test_dangerous_services_are_never_permitted_across_zones_in_the_hardened_network(self):
        risky = {"telnet", "rdp", "smb", "snmp", "syslog"}
        leaks = [(c.sender, c.destination, c.service) for c in self.hardened.cross_zone_permitted if c.service in risky]
        self.assertEqual(leaks, [])

    def test_only_the_administrator_reaches_device_management(self):
        ssh = {(c.sender, c.destination) for c in self.hardened.cross_zone_permitted if c.service == "ssh"}
        self.assertEqual(ssh, {("PC3", "FW-EDGE"), ("PC3", "SW-ACCESS"), ("PC3", "SW-DMZ")})

    def test_intra_zone_traffic_is_reported_as_unfiltered(self):
        cell = next(c for c in self.hardened.cells if (c.sender, c.destination, c.service) == ("PC0", "PC1", "smb"))
        self.assertTrue(cell.delivered and cell.intra_zone and cell.intended)
        self.assertIn("never filtered", cell.why)


class DamagedConfigurations(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def hardened(self) -> mx.Matrix:
        return compute("hardened", self.ws.topology_path, INTENT)

    def test_a_subnet_wide_rule_is_caught_by_the_unused_address_probe(self):
        self.ws.edit("hardened", "FW-EDGE", " permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443\n",
                     " permit tcp 10.10.10.0 0.0.0.255 10.10.20.0 0.0.0.255 eq 443\n")
        found = kinds(self.hardened())
        self.assertIn(("unexpected permit", "PC0", "UNUSED-SERVERS", "https"), found)
        self.assertNotIn(("unexpected permit", "PC0", "SRV-APP", "https"), found, "the real server is allowed https")

    def test_a_forgotten_service_is_reported_as_a_broken_service(self):
        self.ws.edit("hardened", "FW-EDGE", " permit udp 10.10.10.0 0.0.0.255 host 172.16.50.20 eq 53\n", "")
        self.assertIn(("unexpected block", "PC0", "DNS-DMZ", "dns-udp"), kinds(self.hardened()))

    def test_a_missing_reply_rule_is_reported_as_a_broken_service(self):
        self.ws.edit("hardened", "FW-EDGE", " permit tcp host 10.10.20.10 eq 80 10.10.10.0 0.0.0.255 established\n", "")
        self.assertIn(("unexpected block", "PC0", "SRV-APP", "http"), kinds(self.hardened()))

    def test_opening_a_zone_is_caught_everywhere(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-list extended IN-GUEST\n", "ip access-list extended IN-GUEST\n permit ip any any\n")
        found = kinds(self.hardened())
        self.assertIn(("unexpected permit", "PC2", "WEB-DMZ", "ssh"), found, "a request that arrives is a hole even if IN-DMZ drops the reply")
        self.assertIn(("unexpected permit", "PC2", "UNUSED-MGMT", "ssh"), found)
        self.assertIn(("unexpected permit", "PC2", "FW-EDGE-USERS", "icmp"), found)

    def test_opening_the_outside_interface_exposes_the_published_servers_to_everything(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-list extended IN-OUTSIDE\n", "ip access-list extended IN-OUTSIDE\n permit ip any any\n")
        found = kinds(self.hardened())
        self.assertIn(("unexpected permit", "PC5", "WEB-DMZ-PUBLIC", "ssh"), found)
        self.assertIn(("unexpected permit", "PC5", "FW-EDGE-OUTSIDE", "icmp"), found)


class IntentFile(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.topology = load_topology(TOPOLOGY)

    def load(self, body: str) -> mx.Intent:
        path = Path(self._tmp.name, "intent.yaml")
        path.write_text(textwrap.dedent(body))
        return mx.load_intent(path, self.topology)

    def rejects(self, body: str, fragment: str) -> None:
        with self.assertRaises(mx.IntentError) as ctx:
            self.load(body)
        self.assertIn(fragment, str(ctx.exception))

    def test_committed_intent_is_loaded_and_every_rule_is_justified(self):
        intent = mx.load_intent(INTENT, self.topology)
        self.assertGreaterEqual(len(intent.rules), 15)
        self.assertTrue(all(len(r.why) > 10 for r in intent.rules))

    def test_minimal_file(self):
        intent = self.load("schema: 1\nallow: []\n")
        self.assertEqual(intent.services, mx.DEFAULT_SERVICES)

    def test_rejects_malformed_files(self):
        self.rejects("schema: 2\n", "schema: 1")
        self.rejects("schema: 1\nallow:\n  - {from: PC0, to: SRV-APP, services: [http]}\n", "needs from, to, services and why")
        self.rejects("schema: 1\nallow:\n  - {from: PC0, to: SRV-APP, services: [http], why: ' '}\n", "business need")
        self.rejects("schema: 1\nallow:\n  - {from: NOBODY, to: SRV-APP, services: [http], why: x}\n", "NOBODY")
        self.rejects("schema: 1\nallow:\n  - {from: PC0, to: SRV-APP, services: [gopher], why: x}\n", "unknown service")
        self.rejects("schema: 1\ndestinations: {PC0: 10.1.1.1}\n", "clash")
        with self.assertRaises(mx.IntentError):
            mx.load_intent(Path(self._tmp.name, "missing.yaml"), self.topology)


class Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = load_topology(TOPOLOGY)
        cls.intent = mx.load_intent(INTENT, cls.topology)
        cls.matrices = [mx.compute(cls.topology, s, cls.intent) for s in ("baseline", "hardened")]

    def test_markdown(self):
        text = mx.to_markdown(self.matrices, self.topology, self.intent)
        self.assertIn("not Packet Tracer results", text)
        self.assertIn("**No disagreements", text)
        self.assertIn("Disagreements with the policy", text)
        self.assertIn("Employees use the internal application", text)

    def test_csv_lists_permitted_flows_and_disagreements_only_by_default(self):
        rows = list(csv.DictReader(io.StringIO(mx.to_csv(self.matrices))))
        self.assertTrue(all(r["result"] == "permitted" or r["disagreement"] for r in rows))
        everything = list(csv.DictReader(io.StringIO(mx.to_csv(self.matrices, everything=True))))
        self.assertEqual(len(everything), sum(len(m.cells) for m in self.matrices))

    def test_json_and_text(self):
        data = json.loads(mx.to_json(self.matrices))
        self.assertEqual(data["matrices"][1]["summary"]["unexpected_permits"], 0)
        self.assertEqual(data["matrices"][1]["disagreements"], [])
        text = mx.to_text(self.matrices)
        self.assertIn("hardened: 3146 probes", text)
        self.assertIn("unexpected permits 0, unexpected blocks 0", text)


class Command(unittest.TestCase):
    def call(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(list(args))
        return code, out.getvalue()

    def setUp(self):
        cwd = Path.cwd()
        os.chdir(ROOT)
        self.addCleanup(os.chdir, cwd)

    def test_passes_on_the_committed_lab_even_though_the_baseline_disagrees(self):
        code, out = self.call("matrix")
        self.assertEqual(code, 0)
        self.assertIn("baseline:", out)

    def test_fails_when_the_hardened_configuration_leaks(self):
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("hardened", "FW-EDGE", "ip access-list extended IN-GUEST\n", "ip access-list extended IN-GUEST\n permit ip any any\n")
        code, out = self.call("matrix", "--topology", str(ws.topology_path), "--state", "hardened")
        self.assertEqual(code, 1)
        self.assertIn("unexpected permit", out)

    def test_bad_input_is_exit_2(self):
        self.assertEqual(self.call("matrix", "--intent", "missing.yaml")[0], 2)


if __name__ == "__main__":
    unittest.main()
