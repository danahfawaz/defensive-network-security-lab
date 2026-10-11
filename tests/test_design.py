"""Topology loader and design-consistency checker.

A checker that says "OK" proves nothing until it has been seen to fail, so most tests here break one fact in a copy of
the real configurations and expect exactly that check to complain.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from ciscoaudit.policy.design import CHECKS, check_design
from ciscoaudit.policy.topology import STATES, TopologyError, load_topology
from tests.helpers import ROOT


class Workspace:
    """A throw-away copy of topology/ and configs/ that a test may damage."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        shutil.copytree(ROOT / "topology", self.root / "topology")
        for folder in ("baseline", "hardened", "internet-sim"):
            shutil.copytree(ROOT / "configs" / folder, self.root / "configs" / folder)
        self.topology_path = self.root / "topology" / "topology.yaml"

    def close(self) -> None:
        self._tmp.cleanup()

    def edit(self, state: str, device: str, old: str, new: str, count: int = 1) -> None:
        folder = "internet-sim" if device in ("ISP-R", "SW-INET") else state
        path = self.root / "configs" / folder / f"{device}.cfg"
        text = path.read_text()
        if text.count(old) < 1:
            raise AssertionError(f"{old!r} not found in {path.name}")
        path.write_text(text.replace(old, new, count))

    def edit_topology(self, mutate) -> None:
        data = yaml.safe_load(self.topology_path.read_text())
        mutate(data)
        self.topology_path.write_text(yaml.safe_dump(data, sort_keys=False))

    def check(self, state: str):
        return check_design(load_topology(self.topology_path), state)


class RealDesign(unittest.TestCase):
    def test_committed_configurations_implement_the_topology(self):
        topology = load_topology(ROOT / "topology" / "topology.yaml")
        for state in STATES:
            self.assertEqual([str(i) for i in check_design(topology, state)], [], state)

    def test_every_check_code_is_documented(self):
        self.assertEqual(sorted(CHECKS), [f"D-{n:02d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)])

    def test_topology_summary(self):
        t = load_topology(ROOT / "topology" / "topology.yaml")
        self.assertEqual((len(t.devices), len(t.hosts), len(t.zones)), (5, 11, 7))
        self.assertEqual({d.pt_label for d in t.devices.values()} | {r["pt_label"] for r in t.retired},
                         {"Router1", "Router2", "Router3", "Router4", "Switch0", "Switch1", "Switch2"})
        self.assertEqual(t.zone_of("10.10.99.20").name, "mgmt")
        self.assertEqual(t.host_by_ip("198.51.100.66").name, "PC5")
        self.assertEqual(t.admin_host().name, "PC3")
        self.assertEqual(t.config_path("hardened", "FW-EDGE").parent.name, "hardened")
        self.assertEqual(t.config_path("hardened", "ISP-R").parent.name, "internet-sim")  # shared by both states
        with self.assertRaises(TopologyError):
            t.config_path("production", "FW-EDGE")


class BrokenDesign(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def codes(self, state: str = "hardened") -> set[str]:
        return {i.code for i in self.ws.check(state) if i.severity == "error"}

    def messages(self, state: str = "hardened") -> str:
        return "\n".join(str(i) for i in self.ws.check(state))

    def test_wrong_gateway_address(self):
        self.ws.edit("hardened", "FW-EDGE", "ip address 10.10.10.1 255.255.255.0", "ip address 10.10.10.254 255.255.255.0")
        self.assertIn("D-02", self.codes())
        self.assertIn("zone users needs 10.10.10.1/24", self.messages())

    def test_wrong_dot1q_vlan(self):
        self.ws.edit("hardened", "FW-EDGE", "encapsulation dot1Q 20", "encapsulation dot1Q 21")
        self.assertTrue({"D-02", "D-05"} <= self.codes())

    def test_host_port_in_wrong_vlan(self):
        self.ws.edit("hardened", "SW-ACCESS", "description USERS - PC0\n switchport access vlan 10",
                     "description USERS - PC0\n switchport access vlan 20")
        self.assertIn("D-04", self.codes())
        self.assertIn("PC0", self.messages())

    def test_host_port_shut_down(self):
        self.ws.edit("hardened", "SW-ACCESS", "description USERS - PC1\n", "description USERS - PC1\n shutdown\n")
        self.assertTrue({"D-04", "D-05"} <= self.codes())

    def test_trunk_not_pruned_or_wrong_native_vlan_in_hardened_only(self):
        self.ws.edit("hardened", "SW-ACCESS", "switchport trunk allowed vlan 10,20,30,99", "switchport trunk allowed vlan 10,20,30,50,99")
        self.assertIn("D-06", self.codes())
        self.ws.edit("hardened", "SW-ACCESS", "switchport trunk native vlan 999", "switchport trunk native vlan 1")
        self.assertIn("native VLAN 1", self.messages())
        self.assertNotIn("D-06", self.codes("baseline"))  # the baseline trunk is allowed to carry everything

    def test_vlan_not_declared(self):
        self.ws.edit("baseline", "SW-ACCESS", "vlan 30\n name GUEST\n", "")
        self.assertIn("D-06", self.codes("baseline"))

    def test_nat_mismatch(self):
        self.ws.edit("hardened", "FW-EDGE", "ip nat inside source static 172.16.50.10 203.0.113.9",
                     "ip nat inside source static 172.16.50.10 203.0.113.11")
        self.assertIn("D-08", self.codes())
        self.assertIn("missing static NAT 172.16.50.10 -> 203.0.113.9", self.messages())

    def test_pat_scope_is_a_hardened_policy_check(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-list standard NAT-PAT\n permit 10.10.10.0 0.0.0.255\n",
                     "ip access-list standard NAT-PAT\n permit 10.10.10.0 0.0.0.255\n permit 10.10.20.0 0.0.0.255\n")
        self.assertIn("D-08", self.codes())
        self.assertIn("zone servers", self.messages())
        # the (deliberately sloppy) baseline translates all of 10.10.0.0/16 and is still a consistent network
        self.assertNotIn("D-08", self.codes("baseline"))

    def test_missing_default_route_and_isp_return_route(self):
        self.ws.edit("hardened", "FW-EDGE", "ip route 0.0.0.0 0.0.0.0 203.0.113.1\n", "")
        self.assertIn("D-09", self.codes())
        self.ws.edit("hardened", "ISP-R", "ip route 203.0.113.8 255.255.255.248 203.0.113.2\n", "")
        self.assertIn("route to 203.0.113.8/29", self.messages())

    def test_routing_protocol_is_rejected(self):
        self.ws.edit("hardened", "FW-EDGE", "ip classless\n", "ip classless\nrouter rip\n version 2\n network 10.0.0.0\n")
        self.assertIn("static routes only", self.messages())

    def test_missing_null_route_only_matters_when_hardened(self):
        self.ws.edit("hardened", "FW-EDGE", "ip route 203.0.113.8 255.255.255.248 Null0\n", "")
        self.assertIn("D-09", self.codes())
        self.ws.edit("baseline", "FW-EDGE", "ip route 203.0.113.8 255.255.255.248 Null0\n", "")
        self.assertNotIn("D-09", self.codes("baseline"))

    def test_acl_detached_from_zone_interface(self):
        self.ws.edit("hardened", "FW-EDGE", " ip access-group IN-DMZ in\n", "")
        self.assertIn("D-10", self.codes())
        self.assertIn("no inbound ACL", self.messages())
        self.assertNotIn("D-10", self.codes("baseline"))  # the baseline has no zone filtering by design

    def test_acl_that_does_not_end_in_deny(self):
        self.ws.edit("hardened", "FW-EDGE", "permit icmp any host 203.0.113.2 time-exceeded\n deny ip any any log\n",
                     "permit icmp any host 203.0.113.2 time-exceeded\n")
        self.assertIn("D-10", self.codes())

    def test_duplicate_address(self):
        self.ws.edit("hardened", "SW-ACCESS", "ip address 10.10.99.2 255.255.255.0", "ip address 10.10.99.1 255.255.255.0")
        self.assertTrue({"D-07", "D-13"} <= self.codes())

    def test_vty_admits_a_user_host(self):
        self.ws.edit("hardened", "SW-DMZ", "ip access-list standard VTY-ADMIN\n permit host 10.10.99.10\n",
                     "ip access-list standard VTY-ADMIN\n permit host 10.10.99.10\n permit host 10.10.10.10\n")
        self.assertIn("D-12", self.codes())
        self.assertIn("admits PC0", self.messages())

    def test_telnet_enabled_on_vty(self):
        self.ws.edit("hardened", "SW-ACCESS", "transport input ssh", "transport input all", 2)
        self.assertIn("D-12", self.codes())

    def test_syslog_and_ntp_targets(self):
        self.ws.edit("hardened", "FW-EDGE", "logging host 10.10.99.20", "logging host 10.10.99.21")
        self.ws.edit("hardened", "SW-DMZ", "ntp server 10.10.99.20", "ntp server 10.10.99.99")
        msgs = self.messages()
        self.assertIn("does not send syslog to 10.10.99.20", msgs)
        self.assertIn("does not use 10.10.99.20 as NTP server", msgs)

    def test_hostname_must_match_topology(self):
        self.ws.edit("hardened", "SW-DMZ", "hostname SW-DMZ", "hostname Switch")
        self.assertIn("D-01", self.codes())

    def test_dhcp_pool_expectations(self):
        self.ws.edit("hardened", "FW-EDGE", "ip dhcp excluded-address 10.10.30.1 10.10.30.99",
                     "ip dhcp excluded-address 10.10.30.1 10.10.30.50")
        self.assertIn("D-14", self.codes())
        self.assertIn("first lease", self.messages())
        self.ws.edit("hardened", "FW-EDGE", " network 10.10.30.0 255.255.255.0\n", " network 10.10.31.0 255.255.255.0\n")
        self.assertIn("no pool for 10.10.30.0/24", self.messages())

    def test_cable_end_missing_from_configuration(self):
        self.ws.edit("hardened", "SW-DMZ", "interface FastEthernet0/3\n", "interface FastEthernet0/24\n")
        self.assertIn("D-05", self.codes())

    def test_outside_interface_and_isp_addressing(self):
        self.ws.edit("hardened", "FW-EDGE", "ip address 203.0.113.2 255.255.255.252", "ip address 203.0.113.6 255.255.255.252")
        self.assertIn("D-03", self.codes())
        self.ws.edit("hardened", "ISP-R", "ip address 198.51.100.1 255.255.255.0", "ip address 198.51.100.2 255.255.255.0")
        self.assertIn("Internet LAN gateway", self.messages())

    def test_missing_config_file_is_reported_not_raised(self):
        (self.ws.root / "configs" / "hardened" / "SW-DMZ.cfg").unlink()
        issues = self.ws.check("hardened")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].code, "D-01")


class TopologyValidation(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def load_with(self, mutate):
        self.ws.edit_topology(mutate)
        return load_topology(self.ws.topology_path)

    def test_host_outside_its_zone(self):
        with self.assertRaisesRegex(TopologyError, "outside zone users"):
            self.load_with(lambda d: d["hosts"]["PC0"].update(ip="10.10.11.10"))

    def test_duplicate_host_address(self):
        with self.assertRaisesRegex(TopologyError, "duplicate host addresses"):
            self.load_with(lambda d: d["hosts"]["PC1"].update(ip="10.10.10.10"))

    def test_unknown_zone(self):
        with self.assertRaisesRegex(TopologyError, "unknown zone"):
            self.load_with(lambda d: d["hosts"]["PC0"].update(zone="lan"))

    def test_port_cabled_twice(self):
        with self.assertRaisesRegex(TopologyError, "cabled twice"):
            self.load_with(lambda d: d["links"].append({"a": "PC4", "b": "SW-ACCESS:Fa0/1", "kind": "access", "vlan": 10, "origin": "new"}))

    def test_attach_must_agree_with_the_link(self):
        with self.assertRaisesRegex(TopologyError, "'attach' says"):
            self.load_with(lambda d: d["hosts"]["PC0"].update(attach="SW-ACCESS:Fa0/9"))

    def test_overlapping_zones(self):
        with self.assertRaisesRegex(TopologyError, "overlap"):
            self.load_with(lambda d: d["zones"]["guest"].update(subnet="10.10.10.0/25", gateway="10.10.10.1"))

    def test_nat_inside_address_must_match_host(self):
        def mutate(d):
            d["nat"]["static"][0]["inside"] = "172.16.50.99"
        with self.assertRaisesRegex(TopologyError, "does not match the host"):
            self.load_with(mutate)

    def test_not_a_topology_file(self):
        self.ws.topology_path.write_text("hello: world\n")
        with self.assertRaisesRegex(TopologyError, "not a topology file"):
            load_topology(self.ws.topology_path)
        with self.assertRaises(TopologyError):
            load_topology(self.ws.root / "missing.yaml")


if __name__ == "__main__":
    unittest.main()
