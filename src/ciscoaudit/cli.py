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

    v = sub.add_parser("validate", help="run the security validation scenarios (policy simulator + auditor) against the configurations")
    v.add_argument("--topology", default="topology/topology.yaml")
    v.add_argument("--scenarios", default="scenarios/scenarios.yaml")
    v.add_argument("--state", choices=["baseline", "hardened", "all"], default="all")
    v.add_argument("-f", "--format", choices=["text", "markdown", "json", "csv"], default="text")
    v.add_argument("-o", "--output")
    v.add_argument("--only", action="append", metavar="PATTERNS", help="run only scenario ids matching these globs (comma separated, e.g. 'B-*,S-01')")
    v.add_argument("-v", "--verbose", action="store_true", help="text format: print the packet trace of every failure")
    v.add_argument("--title", default="Security validation report", help="markdown title")
    v.add_argument("--pt-plan", metavar="FILE", help="also write the Packet Tracer test plan (Markdown)")
    v.add_argument("--pt-results-template", metavar="FILE", help="also write an empty Packet Tracer results sheet (CSV)")

    m = sub.add_parser("matrix", help="probe every sender against every destination and compare with the written policy")
    m.add_argument("--topology", default="topology/topology.yaml")
    m.add_argument("--intent", default="topology/policy-intent.yaml")
    m.add_argument("--state", choices=["baseline", "hardened", "all"], default="all")
    m.add_argument("-f", "--format", choices=["text", "markdown", "json", "csv"], default="text")
    m.add_argument("-o", "--output")
    m.add_argument("--all", action="store_true", help="csv: include blocked probes as well (large)")
    m.add_argument("--title", default="Reachability matrix")

    t = sub.add_parser("trace", help="follow one flow hop by hop, e.g. \"PC5 -> 203.0.113.9 tcp/22\"")
    t.add_argument("flow", help="'<sender> -> <destination> <proto>/<port> [sport=N] [spoof=IP] [ack] [oneway]'")
    t.add_argument("--topology", default="topology/topology.yaml")
    t.add_argument("--state", choices=["baseline", "hardened", "both"], default="hardened")

    c2 = sub.add_parser("pt-compare", help="compare results recorded from Packet Tracer with the simulator's predictions")
    c2.add_argument("results", help="CSV with the columns id and packet_tracer_result (see evidence/packet-tracer/)")
    c2.add_argument("--topology", default="topology/topology.yaml")
    c2.add_argument("--scenarios", default="scenarios/scenarios.yaml")
    c2.add_argument("-o", "--output")

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


def _load_topology(path: str):
    from .policy.topology import TopologyError, load_topology

    try:
        return load_topology(path)
    except TopologyError as exc:
        raise ValueError(str(exc)) from exc


def _cmd_validate(args: argparse.Namespace) -> int:
    import fnmatch

    from .policy import scenarios as sc, validation_report as vr
    from .policy.topology import STATES, TopologyError

    topology = _load_topology(args.topology)
    scenarios = sc.load_scenarios(args.scenarios, topology)
    patterns = _patterns(args.only)
    if patterns:
        scenarios = [s for s in scenarios if any(fnmatch.fnmatchcase(s.id, p.upper()) for p in patterns)]
        if not scenarios:
            raise ValueError(f"--only {patterns} matches no scenario")
    states = STATES if args.state == "all" else (args.state,)
    try:
        run = sc.run_scenarios(topology, scenarios, tuple(states))
    except TopologyError as exc:
        raise ValueError(str(exc)) from exc
    if args.format == "markdown":
        text = vr.to_markdown(run, title=args.title)
    elif args.format == "json":
        text = vr.to_json(run)
    elif args.format == "csv":
        text = vr.to_csv(run)
    else:
        text = vr.to_text(run, verbose=args.verbose)
    _emit(text, args.output)
    if args.pt_plan:
        _emit(vr.pt_plan_markdown(run, topology), args.pt_plan)
    if args.pt_results_template:
        target = Path(args.pt_results_template)
        if target.is_file() and any(r.get("packet_tracer_result", "not-run").strip() not in ("", "not-run")
                                    for r in __import__("csv").DictReader(target.open(newline="", encoding="utf-8"))):
            raise ValueError(f"{target} already holds recorded Packet Tracer results; refusing to overwrite it with an empty sheet")
        _emit(vr.pt_results_template(run, topology), args.pt_results_template)
    broken_design = [s for s, ok in run.design_ok.items() if not ok]
    if broken_design:
        print(f"ciscoaudit: design checks fail for {', '.join(broken_design)}; run 'ciscoaudit design-check'", file=sys.stderr)
    return EXIT_FINDINGS if run.failures or broken_design else EXIT_OK


def _cmd_matrix(args: argparse.Namespace) -> int:
    from .policy import matrix as mx
    from .policy.topology import STATES, TopologyError

    topology = _load_topology(args.topology)
    intent = mx.load_intent(args.intent, topology)
    states = STATES if args.state == "all" else (args.state,)
    try:
        matrices = [mx.compute(topology, state, intent) for state in states]
    except TopologyError as exc:
        raise ValueError(str(exc)) from exc
    if args.format == "markdown":
        text = mx.to_markdown(matrices, topology, intent, title=args.title)
    elif args.format == "json":
        text = mx.to_json(matrices)
    elif args.format == "csv":
        text = mx.to_csv(matrices, everything=args.all)
    else:
        text = mx.to_text(matrices)
    _emit(text, args.output)
    # the baseline is expected to disagree with the policy; only the hardened configuration is held to it
    return EXIT_FINDINGS if any(m.violations for m in matrices if m.state == "hardened") else EXIT_OK


def _cmd_trace(args: argparse.Namespace) -> int:
    from .policy.engine import Simulator, format_trace
    from .policy.flow import parse_flow
    from .policy.network import load_network
    from .policy.topology import TopologyError

    topology = _load_topology(args.topology)
    flow = parse_flow(args.flow)
    states = ("baseline", "hardened") if args.state == "both" else (args.state,)
    blocks = []
    try:
        for state in states:
            blocks.append(f"[{state}] " + format_trace(Simulator(load_network(topology, state)).run(flow)))
    except TopologyError as exc:
        raise ValueError(str(exc)) from exc
    sys.stdout.write("\n\n".join(blocks) + "\n")
    return EXIT_OK


def _cmd_pt_compare(args: argparse.Namespace) -> int:
    from .policy import scenarios as sc, validation_report as vr

    topology = _load_topology(args.topology)
    run = sc.run_scenarios(topology, sc.load_scenarios(args.scenarios, topology), ("hardened",))
    try:
        text = Path(args.results).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"{args.results}: {exc}") from exc
    result = vr.pt_compare(run, text)
    recorded = len(result["agree"]) + len(result["disagree"])
    lines = [f"recorded Packet Tracer results: {recorded}   agree with the simulator: {len(result['agree'])}   "
             f"disagree: {len(result['disagree'])}   not supported in Packet Tracer: {len(result['not_supported'])}   "
             f"not run yet: {len(result['not_run'])}"]
    done = [m for m in result["manual"] if m["result"] == "succeeded"]
    lines.append(f"manual Packet Tracer checks (X-nn): {len(result['manual'])}   observed: {len(done)}   "
                 f"not run yet: {len(result['manual']) - len(done)}")
    lines += [f"  DISAGREE {d['id']}: simulator {d['simulator']}, Packet Tracer {d['packet_tracer']}" for d in result["disagree"]]
    lines += [f"  unknown scenario id in the CSV: {u}" for u in result["unknown_ids"]]
    _emit("\n".join(lines) + "\n", args.output)
    return EXIT_FINDINGS if result["disagree"] or result["unknown_ids"] else EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = [r for r in all_rules() if not args.category or r.info.category.lower() == args.category.lower()]
    if not rules:
        raise ValueError(f"no rules in category {args.category!r}")
    text = {"json": report.rules_to_json, "markdown": report.rules_to_markdown, "text": report.rules_to_text}[args.format](rules)
    _emit(text, args.output)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {"audit": _cmd_audit, "compare": _cmd_compare, "rules": _cmd_rules, "design-check": _cmd_design_check,
                "validate": _cmd_validate, "matrix": _cmd_matrix, "trace": _cmd_trace, "pt-compare": _cmd_pt_compare}
    try:
        return handlers[args.command](args)
    except (ConfigError, WaiverError, ReportError, ValueError) as exc:  # IntentError and ScenarioError are ValueErrors
        print(f"ciscoaudit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # e.g. piped into `head`
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
