"""The packet-level policy simulator.

Two kinds of tests: what the simulator concludes about the real configurations (the order of ACL, NAT and routing, the reply
path, VTY rules), and what it concludes about copies that were damaged on purpose - a simulator that never says "blocked" or
"delivered" for the wrong reason proves nothing, so each mechanism is shown to change the verdict when it is broken.
"""

from __future__ import annotations

import unittest

from ciscoaudit.policy.engine import Simulator, UnsupportedConfig, format_trace
from ciscoaudit.policy.flow import parse_flow
from ciscoaudit.policy.network import load_network
from ciscoaudit.policy.topology import load_topology
from tests.helpers import ROOT, Workspace


def simulator(state: str = "hardened", topology=None) -> Simulator:
    topo = topology or load_topology(ROOT / "topology" / "topology.yaml")
    return Simulator(load_network(topo, state))


def run(text: str, state: str = "hardened", sim: Simulator | None = None):
    return (sim or simulator(state)).run(parse_flow(text))


class OrderOfOperations(unittest.TestCase):
    def test_inbound_acl_sees_the_public_destination_before_static_nat(self):
        result = run("PC5 -> 203.0.113.9 tcp/80")
        self.assertTrue(result.delivered)
        steps = [h.text for h in result.forward.hops]
        acl = next(i for i, t in enumerate(steps) if "IN-OUTSIDE" in t)
        nat = next(i for i, t in enumerate(steps) if "static NAT 203.0.113.9 -> 172.16.50.10" in t)
        self.assertLess(acl, nat, "the ACL on the outside interface is evaluated before the destination is translated")
        self.assertIn("host 203.0.113.9 eq 80", steps[acl])
        self.assertEqual(result.forward.reached, "WEB-DMZ")

    def test_acl_does_not_match_the_private_address_of_a_published_server(self):
        # a rule written for 172.16.50.10 on the outside interface would never match a packet addressed to 203.0.113.9
        result = run("PC5 -> 203.0.113.9 tcp/22")
        self.assertFalse(result.delivered)
        self.assertEqual((result.blocked_by, result.at), ("IN-OUTSIDE", "FW-EDGE"))

    def test_source_nat_happens_after_routing_and_after_the_inside_acl(self):
        result = run("PC0 -> WEB-EXT tcp/80")
        steps = [h.text for h in result.forward.hops]
        acl = next(i for i, t in enumerate(steps) if "IN-USERS" in t)
        route = next(i for i, t in enumerate(steps) if "static route 0.0.0.0/0" in t)
        pat = next(i for i, t in enumerate(steps) if t.startswith("PAT: 10.10.10.10 -> 203.0.113.2"))
        self.assertTrue(acl < route < pat)

    def test_private_destination_is_unreachable_from_the_internet(self):
        result = run("PC5 -> 172.16.50.10 tcp/80")
        self.assertEqual((result.blocked_by, result.at), ("route", "ISP-R"))
        self.assertIn("no route", result.summary())

    def test_null0_discard_route_kills_hairpin_traffic(self):
        result = run("PC0 -> 203.0.113.9 tcp/80")
        self.assertEqual((result.blocked_by, result.at), ("route", "FW-EDGE"))
        self.assertIn("Null0", result.summary())


class ReplyPath(unittest.TestCase):
    def test_permitted_flow_includes_a_working_reply(self):
        result = run("PC0 -> SRV-APP tcp/443")
        self.assertTrue(result.delivered)
        self.assertIsNotNone(result.reply)
        self.assertIn("established", " ".join(h.text for h in result.reply.hops))

    def test_reply_to_a_pat_connection_uses_the_session(self):
        result = run("PC0 -> WEB-EXT tcp/80")
        self.assertIn("PAT session: 203.0.113.2 -> 10.10.10.10", " ".join(h.text for h in result.reply.hops))
        self.assertEqual(result.reply.reached, "PC0")

    def test_reply_to_a_static_nat_connection_is_translated_back(self):
        result = run("PC5 -> 203.0.113.9 tcp/80")
        self.assertIn("static NAT 172.16.50.10 -> 203.0.113.9 (source", " ".join(h.text for h in result.reply.hops))
        self.assertEqual(result.reply.reached, "PC5")

    def test_one_way_flows_have_no_reply(self):
        self.assertIsNone(run("SW-DMZ -> SRV-LOG udp/514 oneway").reply)
        self.assertIsNone(run("PC5 -> 203.0.113.9 tcp/80 spoof=198.51.100.9").reply)

    def test_removing_the_established_permit_breaks_only_the_reply(self):
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("hardened", "FW-EDGE", " permit tcp host 10.10.20.10 eq 443 10.10.10.0 0.0.0.255 established\n", "")
        result = run("PC0 -> SRV-APP tcp/443", sim=simulator("hardened", load_topology(ws.topology_path)))
        self.assertTrue(result.forward.delivered)
        self.assertFalse(result.delivered)
        self.assertEqual((result.phase, result.blocked_by, result.at), ("reply", "IN-SERVERS", "FW-EDGE"))
        self.assertTrue(result.summary().startswith("reply denied"))


class StatelessFiltering(unittest.TestCase):
    """'established' is the ACK/RST flag check IOS performs, not connection tracking."""

    def test_a_syn_cannot_use_an_established_rule(self):
        result = run("SRV-APP -> PC0 tcp/3389 sport=80")  # looks like the reply rule, but it is a SYN
        self.assertFalse(result.delivered)
        self.assertEqual(result.blocked_by, "IN-SERVERS")

    def test_a_crafted_ack_passes_the_same_rule(self):
        result = run("SRV-APP -> PC0 tcp/3389 sport=80 ack")
        self.assertTrue(result.delivered, "this is the documented limitation of ACL-based filtering")


class AddressedToTheDevice(unittest.TestCase):
    def test_vty_access_class_stops_a_non_admin_host_on_the_same_vlan(self):
        result = run("SRV-LOG -> SW-ACCESS tcp/22")
        self.assertEqual((result.blocked_by, result.at), ("vty", "SW-ACCESS"))
        self.assertIn("VTY-ADMIN", result.summary())
        self.assertIn("switched, no router, no ACL", " ".join(h.text for h in result.forward.hops))

    def test_vty_transport_input_stops_telnet_from_the_admin_host(self):
        result = run("PC3 -> SW-ACCESS tcp/23")
        self.assertEqual(result.blocked_by, "vty")
        self.assertIn("transport input ssh", result.summary())

    def test_admin_ssh_reaches_the_switch(self):
        self.assertTrue(run("PC3 -> SW-ACCESS tcp/22").delivered)

    def test_router_listens_only_on_what_is_enabled(self):
        self.assertEqual(run("PC5 -> 203.0.113.2 tcp/80", "baseline").forward.reached, "FW-EDGE")  # ip http server
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("baseline", "FW-EDGE", "ip http server\n", "no ip http server\n")
        result = run("PC5 -> 203.0.113.2 tcp/80", sim=simulator("baseline", load_topology(ws.topology_path)))
        self.assertEqual(result.blocked_by, "no-service")

    def test_baseline_vty_accepts_telnet_from_anywhere(self):
        result = run("PC5 -> 203.0.113.2 tcp/23", "baseline")
        self.assertTrue(result.delivered)
        self.assertIn("transport default (all), no access-class", " ".join(h.text for h in result.forward.hops))

    def test_echo_to_the_gateway_is_answered_only_if_the_acl_allows_it(self):
        self.assertTrue(run("PC0 -> 10.10.10.1 icmp/echo").delivered)
        self.assertEqual(run("PC0 -> 10.10.99.1 icmp/echo").blocked_by, "IN-USERS")  # the Mgmt-side address of the same router

    def test_dhcp_broadcast_is_served_by_the_router(self):
        result = run("PC2 -> 255.255.255.255 udp/67 sport=68 spoof=0.0.0.0")
        self.assertEqual(result.forward.reached, "FW-EDGE")
        self.assertIn("DHCP server", " ".join(h.text for h in result.forward.hops))

    def test_dhcp_without_a_pool_is_refused(self):
        ws = Workspace()
        self.addCleanup(ws.close)
        ws.edit("hardened", "FW-EDGE", "ip dhcp pool GUEST\n network 10.10.30.0 255.255.255.0", "ip dhcp pool OTHER\n network 10.10.31.0 255.255.255.0")
        result = run("PC2 -> 255.255.255.255 udp/67 sport=68 spoof=0.0.0.0", sim=simulator("hardened", load_topology(ws.topology_path)))
        self.assertEqual(result.blocked_by, "no-service")

    def test_router_originated_traffic_is_not_filtered_on_the_way_out_but_its_reply_is(self):
        result = run("FW-EDGE -> SRV-LOG udp/123 sport=123")
        self.assertTrue(result.forward.delivered)
        self.assertIn("IN-MGMT", " ".join(h.text for h in result.reply.hops))
        self.assertTrue(result.delivered)


class SameSubnet(unittest.TestCase):
    def test_hosts_in_one_vlan_never_meet_the_firewall(self):
        result = run("PC0 -> PC1 tcp/445")
        self.assertTrue(result.delivered)
        self.assertTrue(all(h.stage != "acl" for h in result.forward.hops))


class DamagedConfigurations(unittest.TestCase):
    """Each edit removes one mechanism; the verdict must change, and for the right reason."""

    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.close)

    def sim(self, state: str = "hardened") -> Simulator:
        return simulator(state, load_topology(self.ws.topology_path))

    def test_without_the_anti_spoofing_entry_a_forged_source_gets_through(self):
        self.assertFalse(run("PC5 -> 203.0.113.9 tcp/80 spoof=10.10.10.10").delivered)
        self.ws.edit("hardened", "FW-EDGE", " deny ip 10.0.0.0 0.255.255.255 any log\n", " remark removed\n")
        self.assertTrue(run("PC5 -> 203.0.113.9 tcp/80 spoof=10.10.10.10", sim=self.sim()).delivered)

    def test_a_permit_any_any_on_an_interface_opens_that_zone(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-list extended IN-GUEST\n", "ip access-list extended IN-GUEST\n permit ip any any\n")
        result = run("PC2 -> SRV-APP tcp/443", sim=self.sim())
        self.assertTrue(result.forward.delivered, "the request now reaches the application server")
        # ...but the server's own ACL still refuses to answer a guest: replies are filtered separately
        self.assertEqual((result.phase, result.blocked_by), ("reply", "IN-SERVERS"))

    def test_an_acl_entry_the_model_cannot_evaluate_is_refused_not_skipped(self):
        # a TCP flag match: 'deny tcp ... syn' would be read as a plain deny, a silent change of meaning
        self.ws.edit("hardened", "FW-EDGE", " permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443\n",
                     " permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443 syn\n")
        with self.assertRaises(UnsupportedConfig) as ctx:
            run("PC0 -> SRV-APP tcp/443", sim=self.sim())
        self.assertIn("IN-USERS", str(ctx.exception))

    def test_an_unparsable_acl_entry_is_refused_not_skipped(self):
        self.ws.edit("hardened", "FW-EDGE", " permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443\n",
                     " permit tcp 10.10.10.0 0.0.0.255 host 10.10.20.10 eq 443 frobnicate\n")
        with self.assertRaises(UnsupportedConfig):
            run("PC0 -> SRV-APP tcp/443", sim=self.sim())

    def test_removing_static_nat_breaks_the_published_service(self):
        self.ws.edit("hardened", "FW-EDGE", "ip nat inside source static 172.16.50.10 203.0.113.9\n", "")
        result = run("PC4 -> 203.0.113.9 tcp/80", sim=self.sim())
        self.assertFalse(result.delivered)

    def test_removing_the_discard_route_changes_the_hairpin_result(self):
        self.ws.edit("hardened", "FW-EDGE", "ip route 203.0.113.8 255.255.255.248 Null0\n", "")
        result = run("PC0 -> 203.0.113.9 tcp/80", sim=self.sim())
        self.assertNotEqual(result.blocked_by, "route")

    def test_an_interface_acl_that_is_not_defined_permits_everything(self):
        self.ws.edit("hardened", "FW-EDGE", "ip access-group IN-GUEST in", "ip access-group NO-SUCH-ACL in")
        result = run("PC2 -> SRV-APP tcp/443", sim=self.sim())
        self.assertTrue(result.forward.delivered)
        self.assertIn("not defined, IOS permits everything", " ".join(h.text for h in result.forward.hops))

    def test_shutting_the_zone_interface_drops_its_traffic(self):
        self.ws.edit("hardened", "FW-EDGE", " ip address 10.10.20.1 255.255.255.0\n", " ip address 10.10.20.1 255.255.255.0\n shutdown\n")
        result = run("PC0 -> SRV-APP tcp/443", sim=self.sim())
        self.assertFalse(result.delivered)

    def test_removing_the_vty_access_class_opens_the_switch_to_the_whole_vlan(self):
        self.ws.edit("hardened", "SW-ACCESS", " access-class VTY-ADMIN in\n", "", count=2)
        self.assertTrue(run("SRV-LOG -> SW-ACCESS tcp/22", sim=self.sim()).delivered)

    def test_a_routing_loop_is_reported_not_followed_forever(self):
        self.ws.edit("baseline", "ISP-R", "ip classless\n", "ip classless\nip route 0.0.0.0 0.0.0.0 203.0.113.2\n")
        result = run("PC0 -> 8.8.8.8 tcp/80", sim=self.sim("baseline"))
        self.assertFalse(result.delivered)
        self.assertIn("loop", result.summary())


class Resolution(unittest.TestCase):
    def test_unknown_names_are_rejected(self):
        with self.assertRaises(ValueError):
            run("NOBODY -> SRV-APP tcp/80")
        with self.assertRaises(ValueError):
            run("PC0 -> not-an-address tcp/80")

    def test_an_address_without_a_host_is_reported_as_such(self):
        result = run("PC0 -> 10.10.10.200 icmp/echo")
        self.assertTrue(result.forward.delivered)
        self.assertIn("no known host", result.summary())

    def test_to_dict_and_trace_formatting(self):
        result = run("PC5 -> 203.0.113.9 tcp/22")
        data = result.to_dict()
        self.assertEqual((data["verdict"], data["blocked_by"], data["at"], data["phase"]), ("blocked", "IN-OUTSIDE", "FW-EDGE", "request"))
        self.assertIsNone(data["reply"])
        self.assertNotIn("request", result.to_dict(trace=False))
        text = format_trace(result)
        self.assertIn("denied at FW-EDGE", text)
        self.assertIn("request:", text)


if __name__ == "__main__":
    unittest.main()
