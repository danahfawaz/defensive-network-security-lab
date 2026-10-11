"""Command-line interface for ciscoaudit."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import __version__, compare as comparison, report
from .audit import audit_files, select_rules
from .compare import ReportError, load_report
from .model import Severity
from .parser import ConfigError
from .rules import all_rules
from .waivers import WaiverError, load_waivers

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
_LEVELS = [s.label for s in sorted(Severity)]


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _patterns(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    return [p for v in values for p in v.split(",") if p.strip()]


def _emit(text: str, output: str | None) -> None:
    if output and output != "-":
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ciscoaudit",
                                     description="Audit exported Cisco IOS configurations for insecure settings.")
    parser.add_argument("--version", action="version", version=f"ciscoaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="audit configuration files or directories")
    a.add_argument("paths", nargs="+", help="configuration files, or directories containing *.cfg/*.conf/*.txt files")
    a.add_argument("-f", "--format", choices=["text", "json", "markdown", "csv"], default="text")
    a.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    a.add_argument("--waivers", help="YAML file of accepted-risk waivers")
    a.add_argument("--rules", action="append", metavar="PATTERNS", help="run only these rule ids/globs (comma separated, e.g. 'AUTH-*,L2-001')")
    a.add_argument("--exclude-rules", action="append", metavar="PATTERNS", help="skip these rule ids/globs")
    a.add_argument("--min-severity", type=_severity, metavar="LEVEL", help=f"hide findings below this level ({', '.join(_LEVELS)})")
    a.add_argument("--fail-on", type=_severity, metavar="LEVEL", help="exit 1 if an open finding is at or above this level")
    a.add_argument("--recursive", action="store_true", help="descend into sub-directories")
    a.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour in text output")
    a.add_argument("-v", "--verbose", action="store_true", help="text format: show evidence and remediation")
    a.add_argument("--title", help="report title (markdown/json)")
    a.add_argument("--timestamp", action="store_true", help="add generated_at to JSON (off by default for reproducible reports)")
    a.add_argument("--today", type=date.fromisoformat, metavar="YYYY-MM-DD", help="date used to evaluate waiver expiry")

    c = sub.add_parser("compare", help="compare two JSON audit reports (before/after remediation)")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--map", action="append", default=[], metavar="OLD=NEW", help="match a renamed device (repeatable)")
    c.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    c.add_argument("-o", "--output")
    c.add_argument("--before-label", default="Before")
    c.add_argument("--after-label", default="After")

    d = sub.add_parser("design-check", help="check that the device configurations implement topology/topology.yaml")
    d.add_argument("--topology", default="topology/topology.yaml")
    d.add_argument("--state", choices=["baseline", "hardened", "all"], default="all")
    d.add_argument("-f", "--format", choices=["text", "json"], default="text")
    d.add_argument("-o", "--output")

    r = sub.add_parser("rules", help="list the audit rules")
    r.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    r.add_argument("--category")
    r.add_argument("-o", "--output")
    return parser


def _cmd_audit(args: argparse.Namespace) -> int:
    rules = select_rules(_patterns(args.rules), _patterns(args.exclude_rules) or ())
    waivers = load_waivers(args.waivers) if args.waivers else []
    result = audit_files(args.paths, rules=rules, waivers=waivers, today=args.today, recursive=args.recursive)
    shown = report.filter_by_severity(result, args.min_severity)
    if args.format == "json":
        text = report.to_json(shown, title=args.title, timestamp=args.timestamp, min_severity=args.min_severity)
    elif args.format == "markdown":
        text = report.to_markdown(shown, title=args.title, min_severity=args.min_severity)
    elif args.format == "csv":
        text = report.to_csv(shown)
    else:
        use_color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and not args.output)
        text = report.to_text(shown, color=use_color, verbose=args.verbose, min_severity=args.min_severity)
    _emit(text, args.output)
    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.open_findings()):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_compare(args: argparse.Namespace) -> int:
    mapping = {}
    for item in args.map:
        old, sep, new = item.partition("=")
        if not sep or not old or not new:
            raise ValueError(f"--map expects OLD=NEW, got {item!r}")
        mapping[old] = new
    diff = comparison.compare(load_report(args.before), load_report(args.after), mapping)
    if args.format == "json":
        text = comparison.to_json(diff)
    elif args.format == "markdown":
        text = comparison.to_markdown(diff, before_label=args.before_label, after_label=args.after_label)
    else:
        text = comparison.to_text(diff)
    _emit(text, args.output)
    return EXIT_OK


def _cmd_design_check(args: argparse.Namespace) -> int:
    from .policy.design import CHECKS, check_design
    from .policy.topology import STATES, TopologyError, load_topology

    try:
        topology = load_topology(args.topology)
    except TopologyError as exc:
        raise ValueError(str(exc)) from exc
    states = STATES if args.state == "all" else (args.state,)
    results = {state: check_design(topology, state) for state in states}
    errors = sum(1 for issues in results.values() for i in issues if i.severity == "error")
    if args.format == "json":
        import json

        text = json.dumps({"topology": str(args.topology), "checks": CHECKS,
                           "states": {s: [i.__dict__ for i in issues] for s, issues in results.items()},
                           "errors": errors}, indent=2) + "\n"
    else:
        lines = []
        for state, issues in results.items():
            lines.append(f"{state}: {'OK' if not issues else f'{len(issues)} issue(s)'} "
                         f"({len(CHECKS)} checks, {len(topology.devices)} devices, {len(topology.hosts)} hosts, {len(topology.links)} links)")
            lines += [f"  {i}" for i in issues]
        text = "\n".join(lines) + "\n"
    _emit(text, args.output)
    return EXIT_FINDINGS if errors else EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = [r for r in all_rules() if not args.category or r.info.category.lower() == args.category.lower()]
    if not rules:
        raise ValueError(f"no rules in category {args.category!r}")
    text = {"json": report.rules_to_json, "markdown": report.rules_to_markdown, "text": report.rules_to_text}[args.format](rules)
    _emit(text, args.output)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {"audit": _cmd_audit, "compare": _cmd_compare, "rules": _cmd_rules, "design-check": _cmd_design_check}
    try:
        return handlers[args.command](args)
    except (ConfigError, WaiverError, ReportError, ValueError) as exc:
        print(f"ciscoaudit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # e.g. piped into `head`
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
