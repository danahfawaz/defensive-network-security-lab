"""AUTH-*, MGMT-* and CRED-* rules: each rule is shown firing on a weak config and staying quiet on a good one."""

from ciscoaudit.md5crypt import md5_crypt
from ciscoaudit.model import Severity
from tests.helpers import RuleCase, router, switch


class Auth(RuleCase):
    def test_auth_001_vty_without_authentication(self):
        (f,) = self.fires("AUTH-001", router("line vty 0 4\n no login\n"))
        self.assertEqual((f.severity, f.affected, f.evidence[0].text), (Severity.CRITICAL, ["line vty 0 4"], "no login"))
        self.quiet("AUTH-001", router("line vty 0 4\n login local\n"))
        self.quiet("AUTH-001", router("line vty 0 4\n login\n"))  # unusable, but not unauthenticated

    def test_auth_002_console_and_aux(self):
        (f,) = self.fires("AUTH-002", router("line con 0\nline aux 0\nline vty 0 4\n login local\n"))
        self.assertEqual(f.affected, ["line con 0", "line aux 0"])
        self.fires("AUTH-002", router("line con 0\n no login\n login local\n no login\n"))
        self.quiet("AUTH-002", router("line con 0\n login local\nline aux 0\n no exec\n"))
        self.quiet("AUTH-002", router("line con 0\n login local\nline aux 0\n transport input none\n"))
        self.quiet("AUTH-002", switch("line con 0\n login authentication CON-LIST\n"))

    def test_auth_002_aaa_default_list_authenticates_a_bare_console(self):
        self.quiet("AUTH-002", router("aaa new-model\naaa authentication login default local\nline con 0\n"))
        self.fires("AUTH-002", router("aaa new-model\nline con 0\n"))  # AAA on, but no login method defined

    def test_auth_003_shared_vty_password(self):
        (f,) = self.fires("AUTH-003", router("line vty 0 4\n login\n password hunter2\n"))
        self.assertEqual(f.affected, ["line vty 0 4"])
        self.quiet("AUTH-003", router("line vty 0 4\n login local\n"))
        self.quiet("AUTH-003", router("line vty 0 4\n login\n"))

    def test_auth_004_login_without_password(self):
        (f,) = self.fires("AUTH-004", router("line vty 0 4\n login\nline con 0\n login\n password x\n"))
        self.assertEqual(f.affected, ["line vty 0 4"])
        self.quiet("AUTH-004", router("line vty 0 4\n login local\n"))


class Management(RuleCase):
    def test_mgmt_001_telnet(self):
        (f,) = self.fires("MGMT-001", router("line vty 0 4\n login local\n"))
        self.assertIn("IOS default", f.detail)
        self.fires("MGMT-001", router("line vty 0 4\n transport input all\n"))
        self.fires("MGMT-001", router("line vty 0 4\n transport input telnet ssh\n"))
        self.quiet("MGMT-001", router("line vty 0 4\n transport input ssh\n"))
        self.quiet("MGMT-001", router("line vty 0 4\n transport input none\n"))

    def test_mgmt_002_vty_access_class(self):
        self.fires("MGMT-002", router("line vty 0 4\n login local\n"))
        permissive = "ip access-list standard ANY\n permit any\nline vty 0 4\n access-class ANY in\n"
        (f,) = self.fires("MGMT-002", router(permissive))
        self.assertIn("permits any source", f.detail)
        restrictive = ("ip access-list standard MGMT\n permit host 10.1.99.10\n deny any log\n"
                       "line vty 0 4\n access-class MGMT in\n")
        self.quiet("MGMT-002", router(restrictive))
        # a line that accepts no remote sessions has no audience to restrict
        self.quiet("MGMT-002", router("line vty 0 4\n login local\n transport input none\n"))

    def test_mgmt_003_exec_timeout(self):
        self.fires("MGMT-003", router("line con 0\n exec-timeout 0 0\n"))
        (f,) = self.fires("MGMT-003", router("line vty 0 4\n exec-timeout 30 0\n"))
        self.assertIn("30 min", f.detail)
        self.quiet("MGMT-003", router("line vty 0 4\n exec-timeout 5 0\n"))
        self.quiet("MGMT-003", router("line vty 0 4\n login local\n"))  # default (10 min) is acceptable

    def test_mgmt_004_banner(self):
        self.fires("MGMT-004", router("hostname R1\n"))
        self.quiet("MGMT-004", router("banner motd ^C\nAuthorised use only\n^C\n"))
        self.quiet("MGMT-004", router("banner login #Authorised use only#\n"))

    def test_mgmt_005_http_server(self):
        self.fires("MGMT-005", router("ip http server\n"))
        self.quiet("MGMT-005", router("no ip http server\n"))
        self.quiet("MGMT-005", router("hostname R1\n"))

    def test_mgmt_006_aux(self):
        self.fires("MGMT-006", router("line aux 0\n"))
        self.quiet("MGMT-006", router("line aux 0\n no exec\n transport input none\n"))
        self.quiet("MGMT-006", switch("line con 0\n"))  # rule is router-only

    def test_mgmt_007_default_snmp_community(self):
        (f,) = self.fires("MGMT-007", router("snmp-server community public RO\nsnmp-server community private RW\n"))
        self.assertEqual(f.affected, ["public", "private"])
        self.quiet("MGMT-007", router("snmp-server community Xk9-unguessable RO\n"))

    def test_mgmt_008_snmp_rw(self):
        self.fires("MGMT-008", router("snmp-server community Xk9-unguessable RW\n"))
        self.quiet("MGMT-008", router("snmp-server community Xk9-unguessable RO\n"))

    def test_mgmt_009_aaa(self):
        self.fires("MGMT-009", router("hostname R1\n"))
        self.quiet("MGMT-009", router("aaa new-model\n"))

    def test_mgmt_010_ssh_version(self):
        (f,) = self.fires("MGMT-010", router("hostname R1\n"))
        self.assertEqual(f.severity, Severity.MEDIUM)
        (f,) = self.fires("MGMT-010", router("ip ssh version 1\n"))
        self.assertEqual(f.severity, Severity.HIGH)
        self.quiet("MGMT-010", router("ip ssh version 2\n"))
        self.quiet("MGMT-010", router("line vty 0 4\n transport input none\nline vty 5 15\n transport input none\n"))
        self.fires("MGMT-010", router("line vty 0 4\n transport input none\nline vty 5 15\n transport input ssh\n"))


STRONG = md5_crypt("correct horse battery staple", "abcd")  # a type-5 value of a non-dictionary passphrase


class Credentials(RuleCase):
    def test_cred_001_enable_secret(self):
        self.fires("CRED-001", router("hostname R1\n"))
        self.quiet("CRED-001", router(f"enable secret 5 {STRONG}\n"))
        self.quiet("CRED-001", router("enable password x\n"))  # weak, but CRED-002 reports that
        self.fires("CRED-001", router("enable secret level 5 5 abc\n"))  # a level-5 secret does not protect level 15

    def test_cred_002_reversible_credentials(self):
        text = (
            "enable password cisco\n"
            "username a password 0 plainpw\n"
            "username b password 7 0822455D0A16\n"
            "enable secret plainsecret\n"
            "line vty 0 4\n password linepw\n"
        )
        (f,) = self.fires("CRED-002", router(text))
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(len(f.affected), 5)
        self.assertNotIn("plainpw", f.detail + "".join(e.text for e in f.evidence if "password" not in e.text))
        good = f"enable secret 5 {STRONG}\nusername a secret 5 {STRONG}\nline vty 0 4\n login local\n"
        self.quiet("CRED-002", router(good))

    def test_cred_003_type4(self):
        self.fires("CRED-003", router("enable secret 4 Ynz3m5dlgZiOpNjmdmqIFnhyZpWzCcaCMNd4Wh8WuBU\n"))
        self.quiet("CRED-003", router(f"enable secret 5 {STRONG}\n"))

    def test_cred_004_weak_passwords_in_every_storage_form(self):
        cisco_md5 = md5_crypt("cisco", "mERr")
        text = (
            f"enable secret 5 {cisco_md5}\n"          # type 5
            "username a password 7 0822455D0A16\n"    # type 7
            "username b password 0 admin\n"           # plain
            "line vty 0 4\n password class\n"         # plain line password
        )
        (f,) = self.fires("CRED-004", router(text))
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(len(f.affected), 4)
        blob = f.detail + "".join(e.text for e in f.evidence)
        self.assertNotIn("hx5rVt7rPNoS4wqbXKX7m0", blob, "hash must be redacted")
        self.quiet("CRED-004", router(f"enable secret 5 {STRONG}\nusername a secret 5 {STRONG}\n"))

    def test_cred_005_password_encryption(self):
        (f,) = self.fires("CRED-005", router("no service password-encryption\n"))
        self.assertEqual(f.severity, Severity.LOW)  # nothing sensitive is exposed
        self.assertEqual(f.evidence[0].text, "no service password-encryption")
        (f,) = self.fires("CRED-005", router("username a password 0 x\n"))
        self.assertEqual(f.severity, Severity.MEDIUM)  # a clear-text credential is exposed
        self.quiet("CRED-005", router("service password-encryption\n"))
