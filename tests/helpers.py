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
