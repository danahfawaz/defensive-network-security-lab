"""The one-line flow syntax used by the scenario files."""

from __future__ import annotations

import unittest

from ciscoaudit.policy.flow import EPHEMERAL_PORT, FlowError, FlowSpec, parse_flow


class ParseFlow(unittest.TestCase):
    def test_tcp_flow(self):
        f = parse_flow("PC0 -> SRV-APP tcp/443")
        self.assertEqual((f.src, f.dst, f.proto, f.dport), ("PC0", "SRV-APP", "tcp", 443))
        self.assertTrue(f.expects_reply)
        self.assertEqual(f.source_port, EPHEMERAL_PORT)

    def test_options(self):
        f = parse_flow("PC5 -> 203.0.113.9 tcp/80 sport=1234 spoof=10.10.10.10")
        self.assertEqual((f.sport, f.spoof), (1234, "10.10.10.10"))
        self.assertFalse(f.expects_reply, "a forged source never receives the reply")

    def test_flags(self):
        self.assertFalse(parse_flow("SRV-APP -> PC0 tcp/3389 sport=80 ack").expects_reply)
        self.assertFalse(parse_flow("SW-DMZ -> SRV-LOG udp/514 oneway").expects_reply)
        self.assertTrue(parse_flow("SW-DMZ -> SRV-LOG udp/123 sport=123").expects_reply)

    def test_icmp(self):
        self.assertEqual(parse_flow("PC0 -> PC1 icmp/echo").icmp_type, "echo")
        self.assertEqual(parse_flow("PC0 -> PC1 icmp").icmp_type, "echo")
        self.assertTrue(parse_flow("PC0 -> PC1 icmp/echo").expects_reply)
        self.assertFalse(parse_flow("PC0 -> PC1 icmp/unreachable").expects_reply)

    def test_round_trip_through_str(self):
        for text in ("PC0 -> SRV-APP tcp/443", "PC5 -> 203.0.113.9 tcp/80 sport=1234 spoof=10.10.10.10",
                     "SRV-APP -> PC0 tcp/3389 sport=80 ack", "SW-DMZ -> SRV-LOG udp/514 oneway", "PC0 -> PC1 icmp/echo"):
            self.assertEqual(str(parse_flow(text)), text)
            self.assertEqual(parse_flow(str(parse_flow(text))), parse_flow(text))

    def test_extra_spaces_are_fine(self):
        self.assertEqual(parse_flow("  PC0   ->   SRV-APP   tcp/80  "), FlowSpec("PC0", "SRV-APP", "tcp", 80))


class RejectBadFlows(unittest.TestCase):
    def rejects(self, text: str, fragment: str) -> None:
        with self.assertRaises(FlowError) as ctx:
            parse_flow(text)
        self.assertIn(fragment, str(ctx.exception))

    def test_bad_shape(self):
        self.rejects("PC0 SRV-APP tcp/80", "cannot read flow")
        self.rejects("", "cannot read flow")

    def test_bad_protocol_and_ports(self):
        self.rejects("PC0 -> SRV-APP gre/1", "protocol must be one of")
        self.rejects("PC0 -> SRV-APP tcp", "needs a destination port")
        self.rejects("PC0 -> SRV-APP tcp/70000", "port number")
        self.rejects("PC0 -> SRV-APP tcp/http", "port number")
        self.rejects("PC0 -> SRV-APP icmp/ping", "icmp type")

    def test_bad_options(self):
        self.rejects("PC0 -> SRV-APP tcp/80 dport=1", "unknown option")
        self.rejects("PC0 -> SRV-APP tcp/80 fast", "unknown flag")
        self.rejects("PC0 -> SRV-APP tcp/80 spoof=300.1.1.1", "IPv4 address")
        self.rejects("PC0 -> SRV-APP udp/53 ack", "only applies to tcp")
        self.rejects("PC0 -> PC1 icmp/echo sport=5", "no source port")


if __name__ == "__main__":
    unittest.main()
