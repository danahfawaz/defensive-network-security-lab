import ipaddress
import random
import tempfile
import unittest
from pathlib import Path

from ciscoaudit.parser import ConfigError, canon_ifname, expand_range, load_config, parse_config
from tests.helpers import ORIGINAL_LAB, cfg


class LinesAndNoise(unittest.TestCase):
    def test_comments_blank_lines_and_show_run_noise_are_skipped_but_line_numbers_survive(self):
        c = cfg(
            """
            Building configuration...

            Current configuration : 500 bytes
            !
            hostname R1
            !
            interface FastEthernet0/0
             ip address 10.0.0.1 255.255.255.0
            !
            end
            ip http server
            """
        )
        self.assertEqual(c.hostname, "R1")
        iface = c.interface("fa0/0")
        self.assertEqual(iface.line.no, 7)
        self.assertEqual(iface.ip, ipaddress.IPv4Interface("10.0.0.1/24"))
        self.assertIsNone(c.top_one("ip", "http"), "nothing after 'end' is configuration")

    def test_hierarchy_children_and_context(self):
        c = cfg(
            """
            line vty 0 4
             login local
             transport input ssh
            line con 0
             logging synchronous
            """
        )
        vty = c.top_one("line", "vty")
        self.assertEqual([x.text for x in vty.children], ["login local", "transport input ssh"])
        self.assertEqual(vty.children[0].context, "line vty 0 4")
        self.assertEqual(vty.child_starting("transport", "input").rest("transport", "input"), "ssh")

    def test_no_forms_use_last_statement_wins(self):
        c = cfg(
            """
            no service password-encryption
            service password-encryption
            ip http server
            no ip http server
            """
        )
        self.assertTrue(c.state("service", "password-encryption")[0])
        self.assertFalse(c.state("ip", "http", "server")[0])
        self.assertEqual(c.state("ip", "domain-name"), (None, None))

    def test_abbreviated_and_mixed_case_keywords(self):
        c = cfg("Interface Fa0/1\n Switchport Mode Access\n")
        self.assertEqual(c.interface("FastEthernet0/1").explicit_mode, "access")


class Banners(unittest.TestCase):
    def test_multiline_banner_text_is_never_parsed_as_configuration(self):
        c = cfg(
            """
            hostname R1
            banner motd ^C
            Authorized access only
            enable secret 5 $1$fake$fakefakefakefakefakefa
            username evil password 0 hunter2
            ^C
            line vty 0 4
             login local
            """
        )
        self.assertEqual(c.top("enable"), [])
        self.assertEqual(c.users, [])
        banner = c.banners["motd"]
        self.assertIn("Authorized access only", banner.extra)
        self.assertEqual(c.top_one("line", "vty").no, 7)  # 5 banner lines + hostname precede it

    def test_single_line_banner_with_custom_delimiter(self):
        c = cfg("banner login #Keep out#\nhostname R1\n")
        self.assertEqual(c.banners["login"].extra, "Keep out")
        self.assertEqual(c.hostname, "R1")

    def test_unterminated_banner_is_reported_not_fatal(self):
        c = cfg("hostname R1\nbanner motd ^C\nno end in sight\n")
        self.assertTrue(any("not terminated" in w for w in c.warnings))
        self.assertEqual(c.hostname, "R1")


class InterfaceNames(unittest.TestCase):
    def test_canonical_names(self):
        cases = {
            "Fa0/1": "FastEthernet0/1",
            "fa 0/1": "FastEthernet0/1",
            "gi0/0.10": "GigabitEthernet0/0.10",
            "Gig0/1": "GigabitEthernet0/1",
            "Te1/1": "TenGigabitEthernet1/1",
            "e0/1/0": "Ethernet0/1/0",
            "Vl99": "Vlan99",
            "lo0": "Loopback0",
            "Po1": "Port-channel1",
            "Serial0/0/0": "Serial0/0/0",
        }
        for raw, expected in cases.items():
            self.assertEqual(canon_ifname(raw), expected, raw)

    def test_range_expansion(self):
        self.assertEqual(
            expand_range("FastEthernet0/1 - 3"),
            ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"],
        )
        self.assertEqual(
            expand_range("fa0/1 - fa0/2 , Gi0/1 - 2"),
            ["FastEthernet0/1", "FastEthernet0/2", "GigabitEthernet0/1", "GigabitEthernet0/2"],
        )
        self.assertEqual(expand_range("Fa0/1-2"), ["FastEthernet0/1", "FastEthernet0/2"])
        self.assertIsNone(expand_range("FastEthernet0/5 - 1"))
        self.assertIsNone(expand_range("garbage"))


class InterfaceViews(unittest.TestCase):
    def test_range_stanza_is_expanded_and_shares_its_commands(self):
        c = cfg(
            """
            interface range FastEthernet0/1 - 3
             switchport mode access
             shutdown
            """
        )
        names = [i.name for i in c.interfaces]
        self.assertEqual(names, ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"])
        self.assertTrue(all(i.shutdown and i.explicit_mode == "access" for i in c.interfaces))
        self.assertTrue(all(i.line.no == 1 for i in c.interfaces))

    def test_later_stanza_overrides_earlier_one_for_the_same_interface(self):
        c = cfg(
            """
            interface range FastEthernet0/1 - 2
             shutdown
            interface FastEthernet0/2
             no shutdown
            """
        )
        self.assertTrue(c.interface("Fa0/1").shutdown)
        self.assertFalse(c.interface("Fa0/2").shutdown)

    def test_ip_address_primary_secondary_negation_and_dhcp(self):
        c = cfg(
            """
            interface FastEthernet0/0
             ip address 10.0.0.1 255.255.255.0
             ip address 10.0.1.1 255.255.255.0 secondary
            interface FastEthernet0/1
             ip address 10.0.2.1 255.255.255.0
             no ip address
            interface FastEthernet1/0
             ip address dhcp
            interface FastEthernet1/1
             ip address 10.0.9.1 255.255.255.0
             ip address 10.0.9.2 255.255.255.0
            """
        )
        self.assertEqual(c.interface("Fa0/0").ip, ipaddress.IPv4Interface("10.0.0.1/24"))
        self.assertIsNone(c.interface("Fa0/1").ip)
        self.assertIsNone(c.interface("Fa1/0").ip)
        self.assertEqual(c.interface("Fa1/1").ip.ip, ipaddress.IPv4Address("10.0.9.2"))

    def test_access_groups(self):
        c = cfg(
            """
            interface FastEthernet0/0.10
             ip access-group USERS-IN in
             ip access-group USERS-OUT out
             no ip access-group USERS-OUT out
            """
        )
        groups = c.interface("Fa0/0.10").access_groups
        self.assertEqual(list(groups), ["in"])
        self.assertEqual(groups["in"][0], "USERS-IN")
        self.assertEqual(c.interface("Fa0/0.10").kind, "subinterface")

    def test_switchport_modes(self):
        c = cfg(
            """
            interface FastEthernet0/1
             switchport mode trunk
            interface FastEthernet0/2
             switchport mode dynamic desirable
            interface FastEthernet0/3
             switchport mode dynamic auto
            interface FastEthernet0/4
            interface FastEthernet0/5
             no switchport
             ip address 10.0.0.1 255.255.255.252
            """
        )
        modes = {i.name: i.explicit_mode for i in c.interfaces}
        self.assertEqual(
            modes,
            {
                "FastEthernet0/1": "trunk",
                "FastEthernet0/2": "dynamic-desirable",
                "FastEthernet0/3": "dynamic-auto",
                "FastEthernet0/4": None,
                "FastEthernet0/5": "routed",
            },
        )


class LineBlocks(unittest.TestCase):
    def test_login_modes(self):
        c = cfg(
            """
            line con 0
            line aux 0
             no exec
            line vty 0 1
             login local
            line vty 2 3
             login
             password 7 060506324F41
            line vty 4 4
             no login
            line vty 5 15
             login authentication VTY-AAA
            """
        )
        modes = {b.label: b.login[0] for b in c.line_blocks}
        self.assertEqual(
            modes,
            {
                "line con 0": "unset",
                "line aux 0": "unset",
                "line vty 0 1": "local",
                "line vty 2 3": "password",
                "line vty 4 4": "none",
                "line vty 5 15": "aaa",
            },
        )
        self.assertTrue(c.lines_of("aux")[0].exec_disabled)

    def test_vty_details(self):
        c = cfg(
            """
            line vty 0 4
             exec-timeout 5 30
             access-class MGMT-ONLY in
             transport input ssh
             password 7 060506324F41
            """
        )
        vty = c.lines_of("vty")[0]
        self.assertEqual((vty.first, vty.last), (0, 4))
        self.assertEqual(vty.exec_timeout_seconds[0], 330)
        self.assertEqual(vty.access_class_in[0], "MGMT-ONLY")
        self.assertEqual(vty.transport_input[0], frozenset({"ssh"}))
        enc, value, _line = vty.password
        self.assertEqual((enc, value), (7, "060506324F41"))

    def test_line_password_without_type(self):
        c = cfg("line con 0\n password cisco\n login\n")
        self.assertEqual(c.lines_of("con")[0].password[:2], (None, "cisco"))


class Users(unittest.TestCase):
    def test_username_forms(self):
        c = cfg(
            """
            username admin privilege 15 secret 5 $1$abcd$abcdefghijklmnopqrstuv
            username ops password 7 0822455D0A16
            username lab password cisco
            username guest nopassword
            username bare
            """
        )
        by_name = {u.name: u for u in c.users}
        self.assertEqual((by_name["admin"].kind, by_name["admin"].enc_type, by_name["admin"].privilege), ("secret", 5, 15))
        self.assertEqual((by_name["ops"].kind, by_name["ops"].enc_type), ("password", 7))
        self.assertEqual((by_name["lab"].kind, by_name["lab"].enc_type, by_name["lab"].value), ("password", None, "cisco"))
        self.assertEqual(by_name["guest"].kind, "nopassword")
        self.assertEqual(by_name["bare"].kind, "none")


class DeviceTypeDetection(unittest.TestCase):
    def test_router_that_also_prints_switch_style_lines_is_still_a_router(self):
        c = cfg(
            """
            spanning-tree mode pvst
            interface FastEthernet0/0
             ip address 192.168.0.1 255.255.255.0
            interface Vlan1
             no ip address
             shutdown
            router rip
             network 192.168.0.0
            """
        )
        self.assertEqual(c.device_type, "router")

    def test_switch_by_content(self):
        c = cfg(
            """
            spanning-tree mode pvst
            interface FastEthernet0/1
             switchport mode access
            interface Vlan1
             no ip address
            """
        )
        self.assertEqual(c.device_type, "switch")

    def test_model_hint_in_header_comment_wins(self):
        c = cfg("! Cisco 2960-24TT, IOS 15.0\nhostname X\n")
        self.assertEqual(c.model, "2960-24TT")
        self.assertEqual(c.device_type, "switch")
        c = cfg("! Cisco 1841, IOS 12.4\nhostname X\n")
        self.assertEqual(c.device_type, "router")

    def test_unknown_when_there_is_nothing_to_go_on(self):
        self.assertEqual(cfg("hostname X\n").device_type, "unknown")


class RealFilesAndRobustness(unittest.TestCase):
    def test_original_lab_files_parse_as_expected(self):
        expected = {
            "Router1": ("router", 3),
            "Router2": ("router", 2),
            "Router3": ("router", 2),
            "Router4": ("router", 2),
            "Switch0": ("switch", 0),
            "Switch1": ("switch", 0),
            "Switch2": ("switch", 0),
        }
        for stem, (kind, n_ip) in expected.items():
            c = load_config(ORIGINAL_LAB / f"{stem}.cfg")
            self.assertEqual(c.name, stem)
            self.assertEqual(c.device_type, kind, stem)
            self.assertEqual(c.hostname, "Router" if kind == "router" else "Switch", stem)
            self.assertEqual(sum(1 for i in c.interfaces if i.ip), n_ip, stem)
            self.assertEqual(c.warnings, [], stem)
        sw = load_config(ORIGINAL_LAB / "Switch0.cfg")
        self.assertEqual(len([i for i in sw.interfaces if i.kind == "physical"]), 26)
        self.assertEqual(sw.model, "2960-24TT")
        self.assertEqual(sw.ios_version, "15.0")

    def test_binary_input_is_refused_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.cfg"
            path.write_bytes(b"\x00\x01\x02garbage")
            with self.assertRaises(ConfigError):
                load_config(path)
            with self.assertRaises(ConfigError):
                load_config(Path(tmp) / "missing.cfg")

    def test_parser_never_raises_on_random_lines(self):
        rng = random.Random(1234)
        words = ["interface", "range", "banner", "^C", "line", "vty", "0", "4", "no", "ip", "address", "-", ",",
                 "username", "password", "secret", "7", "!", "end", "Fa0/1", "access-list", "permit", "any"]
        for _ in range(300):
            lines = []
            for _ in range(rng.randint(1, 12)):
                indent = " " * rng.choice([0, 0, 1, 2])
                lines.append(indent + " ".join(rng.choice(words) for _ in range(rng.randint(0, 6))))
            c = parse_config("\n".join(lines))
            _ = (c.interfaces, c.line_blocks, c.users, c.banners, c.device_type)


if __name__ == "__main__":
    unittest.main()
