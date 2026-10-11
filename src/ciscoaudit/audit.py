"""The audit engine: load configurations, run the rules, apply waivers."""

from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path
from typing import Iterable, Sequence

from .model import AuditResult, Evidence, Finding
from .parser import ConfigError, ConfigLine, DeviceConfig, load_config
from .rules import REGISTRY, Rule
from .rules.base import Hit, RuleInfo
from .waivers import Waiver, apply_waivers

CONFIG_SUFFIXES = {".cfg", ".conf", ".txt", ".ios", ".config"}
MAX_EVIDENCE = 8


def discover(paths: Sequence[str | Path], *, recursive: bool = False) -> list[Path]:
    """Expand directories into configuration files (sorted, so reports are reproducible)."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            walker = p.rglob("*") if recursive else p.iterdir()
            files += sorted(f for f in walker if f.is_file() and f.suffix.lower() in CONFIG_SUFFIXES)
        else:
            files.append(p)
    return files


def select_rules(include: Iterable[str] | None = None, exclude: Iterable[str] = ()) -> list[Rule]:
    """Pick rules by id or glob (``AUTH-001``, ``L2-*``).  Unknown patterns are an error."""
    ids = sorted(REGISTRY)

    def expand(patterns: Iterable[str], label: str) -> set[str]:
        chosen: set[str] = set()
        for pattern in patterns:
            pattern = pattern.strip().upper()
            if not pattern:
                continue
            matched = fnmatch.filter(ids, pattern)
            if not matched:
                raise ValueError(f"{label} pattern {pattern!r} matches no rule (try 'ciscoaudit rules')")
            chosen.update(matched)
        return chosen

    wanted = expand(include, "--rules") if include else set(ids)
    wanted -= expand(exclude, "--exclude-rules")
    return [REGISTRY[i] for i in ids if i in wanted]


def _evidence(items: Iterable[ConfigLine | Evidence | None]) -> list[Evidence]:
    out: list[Evidence] = []
    seen: set[tuple[int | None, str]] = set()
    for item in items:
        if item is None:
            continue
        ev = item.evidence() if isinstance(item, ConfigLine) else item
        key = (ev.line, ev.text)
        if key not in seen:
            seen.add(key)
            out.append(ev)
    return out


def _finding(info: RuleInfo, cfg: DeviceConfig, hit: Hit) -> Finding:
    evidence = _evidence(hit.evidence)
    detail = hit.detail
    if len(evidence) > MAX_EVIDENCE:
        detail += f" ({len(evidence) - MAX_EVIDENCE} more evidence lines omitted; see 'affected')"
        evidence = evidence[:MAX_EVIDENCE]
    return Finding(
        rule_id=info.id,
        title=info.title,
        severity=hit.severity if hit.severity is not None else info.severity,
        category=info.category,
        device=cfg.name,
        file=cfg.path,
        obj=hit.obj,
        detail=detail,
        evidence=evidence,
        risk=info.risk,
        remediation=info.remediation,
        references=info.references,
        affected=list(hit.affected),
    )


def audit_configs(
    configs: Sequence[DeviceConfig],
    *,
    rules: Sequence[Rule] | None = None,
    waivers: Sequence[Waiver] = (),
    today: date | None = None,
    strict: bool = False,
) -> AuditResult:
    """Run ``rules`` (default: all) on already-parsed configurations."""
    selected = list(rules) if rules is not None else select_rules()
    result = AuditResult(devices=list(configs), rules_run=[r.id for r in selected],
                         scope=[c.path for c in configs])
    for cfg in configs:
        result.warnings += [f"{cfg.name}: {w}" for w in cfg.warnings]
        if cfg.device_type == "unknown":
            result.warnings.append(f"{cfg.name}: device type could not be determined; only generic rules were run")
        for rule in selected:
            applies = rule.info.applies_to
            if cfg.device_type == "unknown":
                if set(applies) != {"router", "switch"}:
                    continue
            elif cfg.device_type not in applies:
                continue
            try:
                hits = list(rule.check(cfg))
            except Exception as exc:  # an audit tool must not die on one odd configuration
                if strict:
                    raise
                result.warnings.append(f"{cfg.name}: rule {rule.id} failed ({type(exc).__name__}: {exc})")
                continue
            result.findings += [_finding(rule.info, cfg, hit) for hit in hits]
    result.findings.sort(key=lambda f: (-int(f.severity), f.device, f.rule_id, f.obj))
    if waivers:
        result.warnings += apply_waivers(result.findings, list(waivers), today or date.today())
    return result


def audit_files(
    paths: Sequence[str | Path],
    *,
    rules: Sequence[Rule] | None = None,
    waivers: Sequence[Waiver] = (),
    today: date | None = None,
    recursive: bool = False,
    strict: bool = False,
) -> AuditResult:
    files = discover(paths, recursive=recursive)
    if not files:
        raise ConfigError("no configuration files found (looked for " + ", ".join(sorted(CONFIG_SUFFIXES)) + ")")
    configs = []
    seen: dict[str, Path] = {}
    for f in files:
        cfg = load_config(f)
        if cfg.name in seen:
            raise ConfigError(f"two files share the device name {cfg.name!r}: {seen[cfg.name]} and {f}")
        seen[cfg.name] = f
        configs.append(cfg)
    return audit_configs(configs, rules=rules, waivers=waivers, today=today, strict=strict)
