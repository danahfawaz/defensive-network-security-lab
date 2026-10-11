"""Audit rules.  Importing this package registers every rule module."""

from __future__ import annotations

from . import access, acls, credentials, logging_rules, routing, services, switching  # noqa: F401
from .base import REGISTRY, Hit, Rule, RuleInfo


def all_rules() -> list[Rule]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def get_rule(rule_id: str) -> Rule:
    return REGISTRY[rule_id.upper()]


__all__ = ["REGISTRY", "Hit", "Rule", "RuleInfo", "all_rules", "get_rule"]
