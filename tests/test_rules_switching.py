"""L2-* rules."""

from tests.helpers import RuleCase, router, switch

HARD_ACCESS = (
    "interface {name}\n switchport access vlan 10\n switchport mode access\n switchport port-security\n"
    " switchport port-security maximum 2\n spanning-tree portfast\n spanning-tree bpduguard enable\n"
)
HARD_TRUNK = (
    "interface {name}\n switchport trunk native vlan 999\n switchport trunk allowed vlan 10,99\n"
    " switchport mode trunk\n switchport nonegotiate\n"
)


class Layer2(RuleCase):
    def test_hardened_ports_are_clean_for_every_l2_rule(self):
        text = (HARD_ACCESS.format(name="FastEthernet0/1") + HARD_TRUNK.format(name="GigabitEthernet0/1")
                + "interface FastEthernet0/2\n switchport access vlan 999\n switchport mode access\n shutdown\n"
                + "vtp mode transparent\ninterface Vlan99\n ip address 10.1.99.2 255.255.255.0\ninterface Vlan1\n shutdown\n")
        for rule_id in ("L2-001", "L2-002", "L2-003", "L2-004", "L2-005", "L2-006", "L2-007", "L2-008", "L2-009", "L2-010"):
            self.quiet(rule_id, switch(text))

    def test_l2_rules_do_not_run_on_routers(self):
        for rule_id in ("L2-001", "L2-005", "L2-010"):
            self.quiet(rule_id, router("interface FastEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"))

    def test_l2_001_dtp_dynamic(self):
        (f,) = self.fires("L2-001", switch("interface FastEthernet0/1\ninterface FastEthernet0/2\n switchport mode dynamic desirable\n"
                                           "interface FastEthernet0/3\n switchport mode access\ninterface FastEthernet0/4\n shutdown\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1", "FastEthernet0/2"])

    def test_l2_001_interface_range_is_expanded(self):
        (f,) = self.fires("L2-001", switch("interface range FastEthernet0/1 - 4\n description lab\n"))
        self.assertEqual(len(f.affected), 4)

    def test_l2_002_trunk_negotiation(self):
        self.fires("L2-002", switch("interface GigabitEthernet0/1\n switchport mode trunk\n"))
        self.quiet("L2-002", switch("interface GigabitEthernet0/1\n switchport mode trunk\n switchport nonegotiate\n"))

    def test_l2_003_native_vlan(self):
        self.fires("L2-003", switch("interface GigabitEthernet0/1\n switchport mode trunk\n"))
        self.fires("L2-003", switch("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk native vlan 1\n"))
        self.quiet("L2-003", switch("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk native vlan 999\n"))

    def test_l2_004_allowed_vlans(self):
        self.fires("L2-004", switch("interface GigabitEthernet0/1\n switchport mode trunk\n"))
        self.fires("L2-004", switch("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan all\n"))
        self.quiet("L2-004", switch("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n"))

    def test_l2_005_port_security(self):
        (f,) = self.fires("L2-005", switch("interface FastEthernet0/1\n switchport mode access\n"
                                           "interface FastEthernet0/2\n switchport mode access\n switchport port-security\n"
                                           "interface FastEthernet0/3\n switchport mode access\n switchport port-security maximum 2\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1", "FastEthernet0/3"])  # 'maximum' alone does not enable it
        self.fires("L2-005", switch("interface FastEthernet0/1\n switchport mode access\n switchport port-security\n"
                                    " no switchport port-security\n"))

    def test_l2_006_portfast_and_bpduguard(self):
        (f,) = self.fires("L2-006", switch("interface FastEthernet0/1\n switchport mode access\n"
                                           "interface FastEthernet0/2\n switchport mode access\n spanning-tree portfast\n"
                                           "interface FastEthernet0/3\n switchport mode access\n spanning-tree portfast\n spanning-tree bpduguard enable\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1", "FastEthernet0/2"])

    def test_l2_006_global_defaults_cover_access_ports_only(self):
        defaults = "spanning-tree portfast default\nspanning-tree portfast bpduguard default\n"
        self.quiet("L2-006", switch(defaults + "interface FastEthernet0/1\n switchport mode access\n"))
        (f,) = self.fires("L2-006", switch(defaults + "interface FastEthernet0/1\ninterface FastEthernet0/2\n switchport mode access\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1"])  # dynamic-mode port is not an access port
        self.fires("L2-006", switch("spanning-tree portfast default\ninterface FastEthernet0/1\n switchport mode access\n"))  # no guard

    def test_l2_007_unused_ports(self):
        (f,) = self.fires("L2-007", switch("interface FastEthernet0/1\ninterface FastEthernet0/2\n duplex auto\n speed auto\n"
                                           "interface FastEthernet0/3\n shutdown\ninterface FastEthernet0/4\n description PC0\n"
                                           "interface FastEthernet0/5\n no shutdown\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/5"])

    def test_l2_008_vlan1(self):
        (f,) = self.fires("L2-008", switch("interface FastEthernet0/1\n switchport mode access\n"
                                           "interface FastEthernet0/2\n switchport mode access\n switchport access vlan 1\n"
                                           "interface FastEthernet0/3\n switchport mode access\n switchport access vlan 10\n"
                                           "interface FastEthernet0/4\n switchport mode trunk\n"))
        self.assertEqual(f.affected, ["FastEthernet0/1", "FastEthernet0/2"])

    def test_l2_009_management_svi(self):
        self.fires("L2-009", switch("interface Vlan1\n ip address 10.0.0.2 255.255.255.0\n"))
        self.quiet("L2-009", switch("interface Vlan1\n no ip address\n shutdown\n"))
        self.quiet("L2-009", switch("interface Vlan1\n ip address 10.0.0.2 255.255.255.0\n shutdown\n"))

    def test_l2_010_vtp(self):
        self.fires("L2-010", switch("hostname S1\n"))
        self.fires("L2-010", switch("vtp mode client\n"))
        self.quiet("L2-010", switch("vtp mode transparent\n"))
        self.quiet("L2-010", switch("vtp mode off\n"))
