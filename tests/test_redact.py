import unittest

from ciscoaudit.model import redact


class RedactTests(unittest.TestCase):
    def test_secrets_are_masked(self):
        cases = {
            "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0": "enable secret 5 <redacted>",
            "enable password 7 0822455D0A16": "enable password 7 <redacted>",
            "enable password level 5 hunter2": "enable password level 5 <redacted>",
            "enable secret hunter2": "enable secret <redacted>",
            "username admin privilege 15 secret 5 $1$abcd$abcdefghijklmnopqrstuv": "username admin privilege 15 secret 5 <redacted>",
            "username ops password 0 hunter2": "username ops password 0 <redacted>",
            "password 7 060506324F41": "password 7 <redacted>",
            "password hunter2": "password <redacted>",
            "ip ospf message-digest-key 1 md5 7 0822455D0A16": "ip ospf message-digest-key 1 md5 7 <redacted>",
            "ip ospf message-digest-key 1 md5 hunter2": "ip ospf message-digest-key 1 md5 <redacted>",
            "ip ospf authentication-key hunter2": "ip ospf authentication-key <redacted>",
            "ntp authentication-key 1 md5 hunter2": "ntp authentication-key 1 md5 <redacted>",
            "key-string hunter2": "key-string <redacted>",
            "key-string 7 0822455D0A16": "key-string 7 <redacted>",
            "tacacs-server host 10.1.99.30 key hunter2": "tacacs-server host 10.1.99.30 key <redacted>",
            "radius-server key 7 0822455D0A16": "radius-server key 7 <redacted>",
            "crypto isakmp key hunter2 address 192.0.2.1": "crypto isakmp key <redacted> address 192.0.2.1",
            "snmp-server community Xk9-unguessable RO": "snmp-server community <redacted> RO",
            "snmp-server host 10.1.99.20 version 2c Xk9-unguessable": "snmp-server host 10.1.99.20 version 2c <redacted>",
        }
        for raw, expected in cases.items():
            self.assertEqual(redact(raw), expected, raw)

    def test_well_known_snmp_communities_stay_visible_because_they_are_the_finding(self):
        self.assertEqual(redact("snmp-server community public RO"), "snmp-server community public RO")
        self.assertEqual(redact("snmp-server community PRIVATE RW"), "snmp-server community PRIVATE RW")

    def test_block_scoped_keys(self):
        self.assertEqual(redact("key 7 0822455D0A16", "radius server RAD1"), "key 7 <redacted>")
        self.assertEqual(redact("key hunter2", "tacacs server TAC1"), "key <redacted>")
        self.assertEqual(redact("key 1", "key chain KEYS"), "key 1")  # a key-chain index is not a secret
        self.assertEqual(redact("key hunter2", "interface Fa0/0"), "key hunter2")  # only inside AAA server blocks

    def test_innocuous_lines_are_untouched(self):
        for line in (
            "service password-encryption",
            "no service password-encryption",
            "login local",
            "key chain KEYS",
            "line vty 0 4",
            "ip ssh version 2",
            "transport input ssh",
            "enable use-tacacs",
            "interface FastEthernet0/1",
            "switchport port-security mac-address sticky",
        ):
            self.assertEqual(redact(line), line, line)

    def test_idempotent(self):
        once = redact("username a password 7 0822455D0A16")
        self.assertEqual(redact(once), once)


class MoreCredentialForms(unittest.TestCase):
    CASES = {
        "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key 7 070C285F4D06": "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key 7 <redacted>",
        "server-private 10.2.2.2 key 0 SPkey": "server-private 10.2.2.2 key 0 <redacted>",
        "snmp-server user bob grp v3 auth md5 AuthPass1 priv aes 128 PrivPass1": "snmp-server user bob grp v3 auth md5 <redacted> priv aes 128 <redacted>",
        "standby 1 authentication text HsrpPass": "standby 1 authentication text <redacted>",
        "standby 1 authentication md5 key-string 0 Hs2": "standby 1 authentication md5 key-string 0 <redacted>",
        "standby 1 authentication md5 key-chain CH1": "standby 1 authentication md5 key-chain CH1",
        "vrrp 2 authentication text VrrpPass": "vrrp 2 authentication text <redacted>",
        "pre-shared-key address 1.1.1.1 key PSKkey": "pre-shared-key address 1.1.1.1 key <redacted>",
        "pre-shared-key local 0 LocalKey": "pre-shared-key local 0 <redacted>",
        "wpa-psk ascii 0 WpaKey123": "wpa-psk ascii 0 <redacted>",
        "key config-key password-encryption MasterKey": "key config-key password-encryption <redacted>",
    }

    def test_additional_credential_forms_are_masked(self):
        for text, expected in self.CASES.items():
            with self.subTest(text=text):
                self.assertEqual(redact(text), expected)


if __name__ == "__main__":
    unittest.main()
