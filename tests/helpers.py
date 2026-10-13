"""Shared helpers for the test-suite."""

from __future__ import annotations

import textwrap
from pathlib import Path

from ciscoaudit.parser import DeviceConfig, parse_config

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ORIGINAL_LAB = ROOT / "configs" / "original-lab"


def cfg(text: str, name: str = "test") -> DeviceConfig:
    """Parse an inline configuration (dedented) for a test."""
    return parse_config(textwrap.dedent(text).lstrip("\n"), path=f"<{name}>", name=name)


# --------------------------------------------------------------------------
# Rule-test helpers
# --------------------------------------------------------------------------
import unittest  # noqa: E402

from ciscoaudit.audit import audit_configs, select_rules  # noqa: E402
from ciscoaudit.model import Finding  # noqa: E402


def router(body: str, name: str = "dut") -> DeviceConfig:
    """A configuration the parser classifies as a router (model hint in the header)."""
    return cfg("! Cisco 1841, IOS 12.4\n" + textwrap.dedent(body), name)


def switch(body: str, name: str = "dut") -> DeviceConfig:
    """A configuration the parser classifies as a switch."""
    return cfg("! Cisco 2960-24TT, IOS 15.0\n" + textwrap.dedent(body), name)


def run_rule(rule_id: str, config: DeviceConfig) -> list[Finding]:
    return audit_configs([config], rules=select_rules([rule_id]), strict=True).findings


class RuleCase(unittest.TestCase):
    """Base class: ``fires`` / ``quiet`` assertions for one rule on one configuration."""

    def fires(self, rule_id: str, config: DeviceConfig, count: int = 1) -> list[Finding]:
        found = run_rule(rule_id, config)
        self.assertEqual(len(found), count, f"{rule_id} should produce {count} finding(s), got "
                         f"{[(f.obj, f.detail) for f in found]}")
        return found

    def quiet(self, rule_id: str, config: DeviceConfig) -> None:
        found = run_rule(rule_id, config)
        self.assertEqual(found, [], f"{rule_id} should be silent, got {[(f.obj, f.detail) for f in found]}")


# --------------------------------------------------------------------------
# A damageable copy of the real lab
# --------------------------------------------------------------------------
import shutil  # noqa: E402
import tempfile  # noqa: E402

import yaml  # noqa: E402

from ciscoaudit.policy.design import check_design  # noqa: E402
from ciscoaudit.policy.topology import load_topology  # noqa: E402


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
