import ipaddress
import unittest

from ciscoaudit.acl import ACE, Net, Packet, PortSet, parse_acls
from tests.helpers import cfg


def acl_of(text: str, name: str):
    return cfg(text).acls[name]


def pkt(proto, src, dst, **kw):
    return Packet.make(proto, src, dst, **kw)


class NetAndPorts(unittest.TestCase):
    def test_wildcard_matching_and_covering(self):
        lan = Net.from_network("10.1.10.0/24")
        self.assertTrue(lan.contains(ipaddress.IPv4Address("10.1.10.77")))
        self.assertFalse(lan.contains(ipaddress.IPv4Address("10.1.11.77")))
        self.assertTrue(Net.any().covers(lan))
        self.assertTrue(lan.covers(Net.host("10.1.10.5")))
        self.assertFalse(Net.host("10.1.10.5").covers(lan))
        self.assertFalse(lan.covers(Net.from_network("10.1.0.0/16")))

    def test_non_contiguous_wildcard(self):
        odd = Net(int(ipaddress.IPv4Address("10.0.1.0")), int(ipaddress.IPv4Address("0.255.0.255")))
        self.assertTrue(odd.contains(ipaddress.IPv4Address("10.77.1.99")))
        self.assertFalse(odd.contains(ipaddress.IPv4Address("10.77.2.99")))

    def test_port_sets(self):
        web = PortSet.from_ranges([(80, 80), (443, 443)])
        self.assertTrue(web.contains(443) and not web.contains(8080))
        self.assertTrue(PortSet.from_ranges([(0, 1023)]).covers(web))
        self.assertFalse(web.covers(PortSet.from_ranges([(0, 1023)])))


class ParsingEntries(unittest.TestCase):
    def test_extended_entry_fields(self):
        acl = acl_of(
            """
            ip access-list extended MGMT
             permit tcp host 10.1.99.10 10.1.0.0 0.0.255.255 eq 22 log
             permit udp any eq 123 host 10.1.99.20
             deny   ip any any log
            """,
            "MGMT",
        )
        ssh, ntp, deny = acl.entries
        self.assertEqual((ssh.action, ssh.proto, str(ssh.src), str(ssh.dst), ssh.dport.text, ssh.log),
                         ("permit", "tcp", "host 10.1.99.10", "10.1.0.0 0.0.255.255", "eq 22", True))
        self.assertEqual((ntp.proto, ntp.sport.text, str(ntp.dst)), ("udp", "eq 123", "host 10.1.99.20"))
        self.assertTrue(deny.is_any_any)
        self.assertTrue(all(e.error is None for e in acl.entries))

    def test_named_ports_numeric_ports_and_operators(self):
        acl = acl_of(
            """
            ip access-list extended P
             permit tcp any any eq www
             permit tcp any any eq 443
             permit tcp any any range 20 21
             permit tcp any any gt 1023
             permit tcp any any neq 23
             permit tcp any any eq 80 443 8080
            """,
            "P",
        )
        sets = [e.dport for e in acl.entries]
        self.assertTrue(sets[0].contains(80) and not sets[0].contains(443))
        self.assertTrue(sets[2].contains(21) and not sets[2].contains(22))
        self.assertTrue(sets[3].contains(1024) and not sets[3].contains(1023))
        self.assertTrue(sets[4].contains(22) and not sets[4].contains(23) and sets[4].contains(24))
        self.assertTrue(sets[5].contains(8080) and not sets[5].contains(81))

    def test_icmp_and_other_protocols(self):
        acl = acl_of(
            """
            ip access-list extended I
             permit icmp any any echo
             permit icmp any any 3 13
             permit icmp any any unreachable
             permit ospf any any
             permit 47 any any
             permit eigrp any host 224.0.0.10
            """,
            "I",
        )
        echo, admin, unreach, ospf, gre, eigrp = acl.entries
        self.assertEqual(echo.icmp, (8, None))
        self.assertEqual(admin.icmp, (3, 13))
        self.assertEqual(unreach.icmp, (3, None))
        self.assertEqual((ospf.proto, gre.proto, eigrp.proto), ("ospf", "gre", "eigrp"))

    def test_numbered_standard_and_extended(self):
        c = cfg(
            """
            access-list 10 permit 10.1.99.10
            access-list 10 permit 10.1.98.0 0.0.0.255
            access-list 10 remark management hosts
            access-list 110 permit tcp any any established
            access-list 110 deny ip any any
            """
        )
        std, ext = c.acls["10"], c.acls["110"]
        self.assertEqual((std.kind, std.numbered, len(std.entries), len(std.remarks)), ("standard", True, 2, 1))
        self.assertEqual((ext.kind, len(ext.entries)), ("extended", 2))
        self.assertTrue(std.entries[0].src.is_host)
        self.assertTrue(ext.entries[0].established)

    def test_unparseable_entries_are_flagged_not_fatal(self):
        acl = acl_of(
            """
            ip access-list extended BAD
             permit tcp any any eq banana
             permit frobnicate any any
             permit tcp 10.0.0.1 any
             permit ip any any
            """,
            "BAD",
        )
        errors = [e.error for e in acl.entries]
        self.assertTrue(all(errors[:3]), errors)
        self.assertIsNone(errors[3])
        self.assertEqual(acl.evaluate(pkt("tcp", "1.1.1.1", "2.2.2.2", dport=22)).ace, acl.entries[3])

    def test_sequence_numbers_define_order(self):
        acl = acl_of(
            """
            ip access-list extended S
             20 deny ip any any
             10 permit tcp any any eq 22
            """,
            "S",
        )
        self.assertEqual([e.seq for e in acl.entries], [10, 20])
        self.assertEqual(acl.entries[0].action, "permit")

    def test_remarks_are_not_entries(self):
        acl = acl_of("ip access-list extended R\n remark allow ssh\n permit tcp any any eq 22\n", "R")
        self.assertEqual(len(acl.entries), 1)
        self.assertEqual(len(acl.remarks), 1)


class Evaluation(unittest.TestCase):
    ACL = """
        ip access-list extended OUTSIDE-IN
         deny   ip 10.0.0.0 0.255.255.255 any log
         permit tcp any host 203.0.113.10 eq www
         permit tcp any host 203.0.113.10 eq 443
         permit icmp any any echo-reply
         permit tcp any any established
         deny   ip any any log
        """

    def setUp(self):
        self.acl = acl_of(self.ACL, "OUTSIDE-IN")

    def verdict(self, *a, **kw):
        return self.acl.evaluate(pkt(*a, **kw))

    def test_permits_and_denies_in_order(self):
        self.assertEqual(self.verdict("tcp", "198.51.100.10", "203.0.113.10", dport=443).action, "permit")
        self.assertEqual(self.verdict("tcp", "198.51.100.10", "203.0.113.10", dport=22).action, "deny")
        spoofed = self.verdict("tcp", "10.9.9.9", "203.0.113.10", dport=443)
        self.assertEqual(spoofed.action, "deny")
        self.assertTrue(spoofed.ace.log)

    def test_established_matches_only_ack_or_rst_segments(self):
        syn = self.verdict("tcp", "198.51.100.10", "10.1.10.11", sport=40000, dport=22)
        ack = self.verdict("tcp", "198.51.100.10", "10.1.10.11", sport=40000, dport=22, tcp_ack=True)
        self.assertEqual(syn.action, "deny")
        self.assertEqual(ack.action, "permit")  # the known weakness of stateless "established"

    def test_icmp_types(self):
        self.assertEqual(self.verdict("icmp", "198.51.100.10", "10.1.10.11", icmp_type=0, icmp_code=0).action, "permit")
        self.assertEqual(self.verdict("icmp", "198.51.100.10", "10.1.10.11", icmp_type=8, icmp_code=0).action, "deny")

    def test_implicit_deny_and_empty_acl(self):
        only_permit = acl_of("ip access-list extended X\n permit tcp any any eq 22\n", "X")
        self.assertEqual(only_permit.evaluate(pkt("udp", "1.1.1.1", "2.2.2.2", dport=53)).reason, "implicit-deny")
        empty = acl_of("ip access-list extended E\n", "E")
        self.assertEqual((empty.evaluate(pkt("tcp", "1.1.1.1", "2.2.2.2")).action,
                          empty.evaluate(pkt("tcp", "1.1.1.1", "2.2.2.2")).reason), ("permit", "empty-acl-permit"))

    def test_standard_acl_matches_on_source_only(self):
        acl = acl_of("access-list 10 permit 10.1.99.10\naccess-list 10 deny any log\n", "10")
        self.assertEqual(acl.evaluate(pkt("tcp", "10.1.99.10", "9.9.9.9", dport=1)).action, "permit")
        self.assertEqual(acl.evaluate(pkt("tcp", "10.1.99.11", "9.9.9.9", dport=1)).action, "deny")


class Covering(unittest.TestCase):
    def aces(self, body: str) -> list[ACE]:
        return acl_of("ip access-list extended C\n" + body, "C").entries

    def test_broader_entry_covers_narrower(self):
        a, b = self.aces(" permit ip 10.1.0.0 0.0.255.255 any\n deny tcp host 10.1.2.3 any eq 22\n")
        self.assertTrue(a.covers(b))
        self.assertFalse(b.covers(a))

    def test_ports_protocol_and_established_must_be_contained(self):
        a, b, c, d = self.aces(
            " permit tcp any any range 1 1023\n"
            " permit tcp any any eq 22\n"
            " permit tcp any any eq 8080\n"
            " permit udp any any eq 22\n"
        )
        self.assertTrue(a.covers(b))
        self.assertFalse(a.covers(c))
        self.assertFalse(a.covers(d))

    def test_established_is_narrower_than_plain_tcp(self):
        plain, est = self.aces(" permit tcp any any\n permit tcp any any established\n")
        self.assertTrue(plain.covers(est))
        self.assertFalse(est.covers(plain))

    def test_icmp_type_containment(self):
        wide, narrow, other = self.aces(
            " permit icmp any any unreachable\n permit icmp any any 3 13\n permit icmp any any echo\n"
        )
        self.assertTrue(wide.covers(narrow))
        self.assertFalse(wide.covers(other))


if __name__ == "__main__":
    unittest.main()
