"""scripts/render_configs.py: placeholders in, secrets out, nothing leaks to Git or the terminal."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ROOT

_spec = importlib.util.spec_from_file_location("render_configs", ROOT / "scripts" / "render_configs.py")
render_configs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render_configs)  # type: ignore[union-attr]


def run(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = render_configs.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Rendering(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        shutil.copytree(ROOT / "configs", self.root / "configs", ignore=shutil.ignore_patterns("original-lab"))

    def test_committed_configs_hold_placeholders_only(self):
        self.assertEqual(render_configs.check_placeholders(ROOT), [])
        code, out, _ = run("--check")
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_check_rejects_a_real_hash_and_unknown_credentials(self):
        path = self.root / "configs" / "hardened" / "SW-DMZ.cfg"
        path.write_text(path.read_text().replace("hostname SW-DMZ", "hostname SW-DMZ\nenable secret 5 $1$abcd$hx5rVt7rPNoS4wqbXKX7m0"))
        code, _out, err = run("--check", "--root", str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("SW-DMZ.cfg", err)
        path = self.root / "configs" / "hardened" / "FW-EDGE.cfg"
        path.write_text(path.read_text() + "snmp-server community hunter2 RW\n")
        self.assertIn("FW-EDGE.cfg", run("--check", "--root", str(self.root))[2])

    def test_generate_renders_every_device_without_printing_secrets(self):
        code, out, err = run("--root", str(self.root), "--state", "hardened", "--generate")
        self.assertEqual(code, 0, err)
        store = json.loads((self.root / "lab-secrets.local.json").read_text())
        self.assertEqual(sorted(store), ["FW-EDGE", "ISP-R", "SW-ACCESS", "SW-DMZ", "SW-INET"])
        for device, mine in store.items():
            self.assertEqual(sorted(mine), ["enable", "user:admin"], device)
            rendered = (self.root / "build" / "rendered" / "hardened" / f"{device}.cfg").read_text()
            self.assertNotIn(render_configs.PLACEHOLDER, rendered)
            self.assertIn(f"enable secret {mine['enable']}\n", rendered)
            self.assertIn(f"username admin privilege 15 secret {mine['user:admin']}\n", rendered)
            for secret in mine.values():
                self.assertNotIn(secret, out + err)
                self.assertGreaterEqual(len(secret), 20)
        self.assertEqual(len({s["enable"] for s in store.values()}), 5)  # unique per device

    def test_secrets_file_is_private_and_reused(self):
        run("--root", str(self.root), "--generate")
        path = self.root / "lab-secrets.local.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
        first = path.read_text()
        self.assertEqual(run("--root", str(self.root), "--state", "baseline")[0], 0)  # nothing new needed: no --generate
        self.assertEqual(path.read_text(), first)

    def test_missing_secret_without_generate_is_an_error(self):
        code, _out, err = run("--root", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("--generate", err)

    def test_user_supplied_secrets_are_used(self):
        store = {d: {"enable": f"Enable{d}x1", "user:admin": f"Admin{d}x1"} for d in ("FW-EDGE", "SW-ACCESS", "SW-DMZ", "ISP-R", "SW-INET")}
        (self.root / "lab-secrets.local.json").write_text(json.dumps(store))
        self.assertEqual(run("--root", str(self.root))[0], 0)
        text = (self.root / "build" / "rendered" / "hardened" / "FW-EDGE.cfg").read_text()
        self.assertIn("enable secret EnableFW-EDGEx1\n", text)

    def test_baseline_is_copied_unchanged(self):
        run("--root", str(self.root), "--state", "baseline", "--generate")
        for name in ("FW-EDGE", "SW-ACCESS", "SW-DMZ"):
            self.assertEqual((self.root / "build" / "rendered" / "baseline" / f"{name}.cfg").read_text(),
                             (self.root / "configs" / "baseline" / f"{name}.cfg").read_text())

    def test_generated_secret_policy(self):
        for _ in range(50):
            s = render_configs.generate_secret()
            self.assertTrue(s.isalnum())
            self.assertTrue(any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s))

    def test_gitignore_covers_everything_the_script_writes(self):
        ignored = (ROOT / ".gitignore").read_text()
        self.assertIn("/build/", ignored)
        self.assertIn("lab-secrets.local.json", ignored)

    def test_rendered_secrets_are_present_and_not_on_the_weak_list(self):
        # CRED-002 (plain text) is expected on a *rendered* file: the device hashes the secret when it is pasted.
        # What must hold is that no device is left without an enable secret and none uses a well-known password.
        from ciscoaudit.audit import audit_files, select_rules
        run("--root", str(self.root), "--generate")
        result = audit_files([self.root / "build" / "rendered" / "hardened"], rules=select_rules(["CRED-*"]))
        self.assertEqual([f.rule_id for f in result.findings if f.rule_id in ("CRED-001", "CRED-004")], [])


if __name__ == "__main__":
    unittest.main()
