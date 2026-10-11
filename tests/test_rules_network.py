"""SVC-*, INT-*, LOG-*, RTE-* and ACL-* rules."""

from ciscoaudit.model import Severity
from tests.helpers import RuleCase, router, switch


class Services(RuleCase):
    def test_svc_001_cdp(self):
        self.fires("SVC-001", router("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"))
        self.quiet("SVC-001", router("no cdp run\ninterface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"))
        everywhere_off = ("interface FastEthernet0/0\n no cdp enable\n ip address 10.0.0.1 255.255.255.0\n"
                          "interface FastEthernet0/1\n shutdown\n")
        self.quiet("SVC-001", router(everywhere_off))
        (f,) = self.fires("SVC-001", router("interface FastEthernet0/0\n no cdp enable\ninterface FastEthernet0/1\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1"])

    def test_svc_002_source_route(self):
        self.fires("SVC-002", router("hostname R1\n"))
        self.quiet("SVC-002", router("no ip source-route\n"))
        self.quiet("SVC-002", switch("hostname S1\n"))  # router-only rule

    def test_svc_003_legacy_services(self):
        (f,) = self.fires("SVC-003", router("service tcp-small-servers\nip finger\nip bootp server\n"))
        self.assertEqual(len(f.affected), 3)
        self.quiet("SVC-003", router("no service tcp-small-servers\nno ip finger\nno ip bootp server\n"))
        self.quiet("SVC-003", router("hostname R1\n"))  # absence of an explicit enable is not reported

    def test_svc_004_default_hostname(self):
        self.fires("SVC-004", router("hostname Router\n"))
        self.fires("SVC-004", switch("hostname Switch\n"))
        self.fires("SVC-004", router("ip classless\n"))
        self.quiet("SVC-004", router("hostname HQ-EDGE\n"))

    def test_int_001_proxy_arp(self):
        text = ("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
                "interface FastEthernet0/1\n ip address 10.0.1.1 255.255.255.0\n no ip proxy-arp\n"
                "interface FastEthernet1/0\n ip address 10.0.2.1 255.255.255.0\n shutdown\n"
                "interface FastEthernet1/1\n no ip address\n")
        (f,) = self.fires("INT-001", router(text))
        self.assertEqual(f.affected, ["FastEthernet0/0"])
        self.quiet("INT-001", router("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n no ip proxy-arp\n"))

    def test_int_002_directed_broadcast(self):
        self.fires("INT-002", router("interface FastEthernet0/0\n ip directed-broadcast\n"))
        self.quiet("INT-002", router("interface FastEthernet0/0\n no ip directed-broadcast\n"))


class Logging(RuleCase):
    def test_log_001_syslog(self):
        self.fires("LOG-001", router("logging buffered 4096\nlogging console\nlogging trap informational\n"))
        self.quiet("LOG-001", router("logging host 10.1.99.20\n"))
        self.quiet("LOG-001", router("logging 10.1.99.20\n"))

    def test_log_002_timestamps(self):
        (f,) = self.fires("LOG-002", router("no service timestamps log datetime msec\n"))
        self.assertEqual(f.evidence[0].text, "no service timestamps log datetime msec")
        self.fires("LOG-002", router("hostname R1\n"))
        self.fires("LOG-002", router("service timestamps log uptime\n"))
        self.quiet("LOG-002", router("service timestamps log datetime msec\n"))

    def test_log_003_ntp(self):
        self.fires("LOG-003", router("hostname R1\n"))
        self.quiet("LOG-003", router("ntp server 10.1.99.20\n"))


TWO_RIP_INTERFACES = (
    "interface FastEthernet0/0\n ip address 192.168.0.1 255.255.255.0\n"
    "interface FastEthernet0/1\n ip address 192.168.2.1 255.255.255.0\n"
)


class Routing(RuleCase):
    def test_rte_001_and_002_ripv1(self):
        text = TWO_RIP_INTERFACES + "router rip\n network 192.168.0.0\n network 192.168.2.0\n"
        (f,) = self.fires("RTE-001", router(text))
        self.assertEqual(f.affected, ["FastEthernet0/0", "FastEthernet0/1"])
        self.assertIn("RIPv1 cannot authenticate", f.detail)
        self.fires("RTE-002", router(text))

    def test_rip_network_statements_are_classful(self):
        text = ("interface FastEthernet0/0\n ip address 10.1.10.1 255.255.255.0\n"
                "interface FastEthernet0/1\n ip address 172.16.5.1 255.255.255.0\n"
                "router rip\n network 10.0.0.0\n")
        (f,) = self.fires("RTE-001", router(text))
        self.assertEqual(f.affected, ["FastEthernet0/0"])

    def test_ripv2_with_md5_key_chain_is_clean(self):
        text = (
            "key chain K\n key 1\n  key-string abc123\n"
            "interface FastEthernet0/0\n ip address 192.168.0.1 255.255.255.0\n"
            " ip rip authentication mode md5\n ip rip authentication key-chain K\n"
            "router rip\n version 2\n network 192.168.0.0\n no auto-summary\n"
        )
        self.quiet("RTE-001", router(text))
        self.quiet("RTE-002", router(text))
        self.quiet("RTE-004", router(text))

    def test_rip_key_chain_without_md5_mode_is_plain_text(self):
        text = (
            "interface FastEthernet0/0\n ip address 192.168.0.1 255.255.255.0\n"
            " ip rip authentication key-chain K\n"
            "router rip\n version 2\n network 192.168.0.0\n"
        )
        self.quiet("RTE-001", router(text))
        (f,) = self.fires("RTE-004", router(text))
        self.assertEqual(f.affected, ["FastEthernet0/0"])

    OSPF = (
        "interface FastEthernet0/0\n ip address 10.255.0.2 255.255.255.252\n{wan}"
        "interface FastEthernet0/1\n ip address 10.1.10.1 255.255.255.0\n"
        "interface FastEthernet1/0\n ip address 10.9.9.1 255.255.255.0\n"
        "router ospf 1\n{ospf}"
        " passive-interface default\n no passive-interface FastEthernet0/0\n"
        " network 10.255.0.0 0.0.0.3 area 0\n network 10.1.10.0 0.0.0.255 area 0\n"
    )

    def ospf(self, wan="", ospf=""):
        return router(self.OSPF.format(wan=wan, ospf=ospf))

    def test_rte_001_ospf_only_active_covered_interfaces_count(self):
        (f,) = self.fires("RTE-001", self.ospf())
        self.assertEqual(f.affected, ["FastEthernet0/0"])  # Fa0/1 passive, Fa1/0 not covered by any network statement

    def test_ospf_authentication_modes(self):
        self.quiet("RTE-001", self.ospf(wan=" ip ospf authentication message-digest\n"))
        self.quiet("RTE-001", self.ospf(ospf=" area 0 authentication message-digest\n"))
        self.quiet("RTE-004", self.ospf(wan=" ip ospf authentication message-digest\n"))
        self.fires("RTE-001", self.ospf(wan=" ip ospf authentication null\n"))
        (f,) = self.fires("RTE-004", self.ospf(wan=" ip ospf authentication\n ip ospf authentication-key abc\n"))
        self.assertEqual(f.affected, ["FastEthernet0/0"])
        self.fires("RTE-004", self.ospf(ospf=" area 0 authentication\n"))

    def test_ospf_interface_level_area_command(self):
        text = ("interface FastEthernet0/0\n ip address 10.7.7.1 255.255.255.0\n ip ospf 1 area 0\n"
                "router ospf 1\n router-id 1.1.1.1\n")
        (f,) = self.fires("RTE-001", router(text))
        self.assertEqual(f.affected, ["FastEthernet0/0"])

    def test_rte_002_version(self):
        self.fires("RTE-002", router("router rip\n version 1\n network 10.0.0.0\n"))
        self.quiet("RTE-002", router("router rip\n version 2\n network 10.0.0.0\n"))

    def test_rte_003_passive_interface(self):
        base = TWO_RIP_INTERFACES + "router rip\n version 2\n network 192.168.0.0\n network 192.168.2.0\n"
        (f,) = self.fires("RTE-003", router(base))
        self.assertEqual(f.affected, ["FastEthernet0/0", "FastEthernet0/1"])
        self.quiet("RTE-003", router(base + " passive-interface default\n"))
        self.quiet("RTE-003", router(base + " passive-interface FastEthernet0/1\n"))
        self.fires("RTE-003", router("router eigrp 10\n network 10.0.0.0\n"))


class AccessLists(RuleCase):
    def test_acl_001_permit_any_any(self):
        first = "ip access-list extended A\n permit ip any any\ninterface FastEthernet0/0\n ip access-group A in\n"
        (f,) = self.fires("ACL-001", router(first))
        self.assertEqual(f.severity, Severity.HIGH)
        after_denies = ("ip access-list extended A\n deny ip 10.0.0.0 0.255.255.255 any\n permit ip any any\n"
                        "interface FastEthernet0/0\n ip access-group A in\n")
        (f,) = self.fires("ACL-001", router(after_denies))
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.quiet("ACL-001", router("ip access-list extended A\n permit ip any any\n"))  # unapplied: ACL-005's job
        allowlist = ("ip access-list extended A\n permit tcp any host 203.0.113.10 eq 443\n deny ip any any log\n"
                     "interface FastEthernet0/0\n ip access-group A in\n")
        self.quiet("ACL-001", router(allowlist))

    def test_acl_001_standard_acl_permit_any(self):
        text = "ip access-list standard V\n permit any\nline vty 0 4\n access-class V in\n"
        self.fires("ACL-001", router(text))

    def test_acl_002_final_logged_deny(self):
        base = "interface FastEthernet0/0\n ip access-group A in\n"
        (f,) = self.fires("ACL-002", router("ip access-list extended A\n permit tcp any any eq 22\n" + base))
        self.assertIn("implicit deny", f.detail)
        (f,) = self.fires("ACL-002", router("ip access-list extended A\n permit tcp any any eq 22\n deny ip any any\n" + base))
        self.assertIn("does not log", f.detail)
        self.quiet("ACL-002", router("ip access-list extended A\n permit tcp any any eq 22\n deny ip any any log\n" + base))
        self.quiet("ACL-002", router("ip access-list extended A\n permit tcp any any eq 22\n"))  # not applied to an interface

    def test_acl_003_telnet(self):
        self.fires("ACL-003", router("ip access-list extended A\n permit tcp any any eq 23\n"))
        self.fires("ACL-003", router("ip access-list extended A\n permit tcp any any eq telnet\n"))
        self.quiet("ACL-003", router("ip access-list extended A\n permit tcp any any eq 22\n permit tcp any any range 1 1023\n"))

    def test_acl_004_undefined_acl(self):
        text = "interface FastEthernet0/0\n ip access-group TYPO in\nline vty 0 4\n access-class NOPE in\n"
        (f,) = self.fires("ACL-004", router(text))
        self.assertEqual(f.affected, ["NOPE", "TYPO"])
        defined = "ip access-list extended TYPO\n deny ip any any\ninterface FastEthernet0/0\n ip access-group TYPO in\n"
        self.quiet("ACL-004", router(defined))

    def test_acl_005_unused_acl(self):
        (f,) = self.fires("ACL-005", router("ip access-list extended DEAD\n deny ip any any\naccess-list 10 permit any\n"))
        self.assertEqual(f.affected, ["DEAD", "10"])
        used = "ip access-list extended A\n deny ip any any\ninterface FastEthernet0/0\n ip access-group A in\n"
        self.quiet("ACL-005", router(used))
        numbered = "access-list 10 permit host 10.1.99.10\nline vty 0 4\n access-class 10 in\n"
        self.quiet("ACL-005", router(numbered))

    def test_acl_006_shadowed(self):
        text = ("ip access-list extended A\n permit ip 10.1.0.0 0.0.255.255 any\n"
                " deny tcp host 10.1.2.3 any eq 22\n permit udp any any eq 53\n")
        (f,) = self.fires("ACL-006", router(text))
        self.assertEqual(f.affected, ["A seq 20"])
        self.assertIn("contradicted", f.detail)
        ordered = "ip access-list extended A\n deny tcp host 10.1.2.3 any eq 22\n permit ip 10.1.0.0 0.0.255.255 any\n"
        self.quiet("ACL-006", router(ordered))

    def test_acl_007_no_filtering(self):
        two = ("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
               "interface FastEthernet0/1\n ip address 10.0.1.1 255.255.255.0\n")
        self.fires("ACL-007", router(two))
        with_acl = two + " ip access-group A in\nip access-list extended A\n deny ip any any log\n"
        self.quiet("ACL-007", router(with_acl))
        self.quiet("ACL-007", router("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"))  # one interface only

    def test_acl_008_unparsed(self):
        (f,) = self.fires("ACL-008", router("ip access-list extended A\n permit tcp any any eq banana\n permit ip any any\n"))
        self.assertEqual(f.severity, Severity.INFO)
        self.quiet("ACL-008", router("ip access-list extended A\n permit ip any any\n"))
