"""Command line for AgentBreaker.

    python -m backend.attack.cli scan --suite data/probes/example.yaml --target self --authorized
    python -m backend.attack.cli inject --target self --authorized --kind all

Scope gate: a scan only runs against a target you own. --target must be given,
only the bundled 'self' target is supported for now, and --authorized must be
passed to confirm you own it. This mirrors the authorization that defines real
penetration testing (see docs/SCOPE_AND_ETHICS.md).
"""

import argparse
import sys

from backend.attack.harness import LocalTarget, run_scan, summarize
from backend.attack.injection import build_direct_probes, build_indirect_probes
from backend.attack.leakage import build_leakage_probes, build_sysprompt_probes
from backend.attack.models import severity_name, VULNERABLE
from backend.attack.report import write_report
from backend.attack.scope import build_scope_probes
from backend.attack.scoring import band, score_finding
from backend.attack.suite import load_probes
from backend.defense.llm import OllamaBackend


def main(argv=None):
    parser = argparse.ArgumentParser(prog="backend.attack")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a probe suite file against a target you own")
    scan.add_argument("--suite", required=True, help="Path to a probe suite YAML")
    _add_target_args(scan)

    inject = sub.add_parser("inject", help="Run the built-in prompt injection suite")
    inject.add_argument("--kind", choices=["direct", "indirect", "all"], default="all")
    _add_target_args(inject)

    leak = sub.add_parser("leak", help="Run the data leakage suite (secrets + system prompt)")
    _add_target_args(leak)

    scope = sub.add_parser("scope", help="Run the scope-escape suite")
    _add_target_args(scope)

    compare = sub.add_parser("compare", help="Run a suite against baseline AND hardened targets")
    compare.add_argument("--kind", choices=["direct", "indirect", "leak", "scope", "all"], default="all")
    _add_target_args(compare)

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run(args, load_probes(args.suite))
    if args.command == "inject":
        return _run(args, _injection_probes(args.kind))
    if args.command == "leak":
        return _run(args, build_leakage_probes()[0] + build_sysprompt_probes())
    if args.command == "scope":
        return _run(args, build_scope_probes())
    if args.command == "compare":
        return _compare(args, _suite(args.kind))


def _add_target_args(parser):
    parser.add_argument("--target", required=True, help="Target to test - only 'self' is supported")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own this target")
    parser.add_argument("--model", default="qwen2.5:7b")
    parser.add_argument("--report", help="Write a report to this path (.md or .html)")
    parser.add_argument("--hardened", action="store_true", help="Attack the hardened (defended) agent")


def _suite(kind):
    """Builds a built-in probe list by kind, sharing canaries within each group."""
    if kind == "direct":
        return build_direct_probes()[0]
    if kind == "indirect":
        return build_indirect_probes()[0]
    if kind == "leak":
        return build_leakage_probes()[0] + build_sysprompt_probes()
    if kind == "scope":
        return build_scope_probes()
    # all
    return (_injection_probes("all")
            + build_leakage_probes()[0] + build_sysprompt_probes()
            + build_scope_probes())


def _scope_refusal(args):
    """Returns an exit code if the scan must be refused, or None to proceed."""
    if args.target != "self":
        print("Refused: only the bundled 'self' target is supported. "
              "AgentBreaker does not attack external targets.", file=sys.stderr)
        return 2
    if not args.authorized:
        print("Refused: pass --authorized to confirm you own this target "
              "(see docs/SCOPE_AND_ETHICS.md).", file=sys.stderr)
        return 2
    return None


def _injection_probes(kind):
    """Builds the injection suite, sharing one canary across all probes."""
    canary = None
    probes = []
    if kind in ("direct", "all"):
        direct, canary = build_direct_probes(canary)
        probes += direct
    if kind in ("indirect", "all"):
        indirect, canary = build_indirect_probes(canary)
        probes += indirect
    return probes


def _run(args, probes):
    refusal = _scope_refusal(args)
    if refusal is not None:
        return refusal

    target = LocalTarget(OllamaBackend(model=args.model), hardened=args.hardened)
    findings = run_scan(probes, target)

    for finding in findings:
        if finding.outcome == VULNERABLE:
            score = score_finding(finding)
            verdict = f"VULNERABLE (CVSS {score}, {band(score)})"
        else:
            verdict = "resisted"
        print(f"[{severity_name(finding.probe.severity):8}] {finding.probe.category} "
              f"{finding.probe.probe_id}: {verdict}")

    stats = summarize(findings)
    bypass_rate = 100 * stats["vulnerable"] // stats["total"] if stats["total"] else 0
    worst = max((score_finding(f) for f in findings), default=0.0)
    print(f"\n{stats['vulnerable']}/{stats['total']} probes succeeded "
          f"({bypass_rate}% bypass rate). Worst finding: CVSS {worst} ({band(worst)}).")

    if args.report:
        meta = {"target": args.target, "model": args.model}
        write_report(findings, args.report, meta)
        print(f"Report written to {args.report}")
    return 0


def _compare(args, probes):
    """Runs the same probes against the baseline and the hardened agent, then
    prints a before/after table - the headline result for the README."""
    refusal = _scope_refusal(args)
    if refusal is not None:
        return refusal

    baseline = LocalTarget(OllamaBackend(model=args.model), hardened=False)
    hardened = LocalTarget(OllamaBackend(model=args.model), hardened=True)
    before = run_scan(probes, baseline)
    after = run_scan(probes, hardened)

    b, a = summarize(before), summarize(after)
    print(f"{'probe':40} {'baseline':>10} {'hardened':>10}")
    print("-" * 62)
    for bf, af in zip(before, after):
        b_v = "VULN" if bf.outcome == VULNERABLE else "ok"
        a_v = "VULN" if af.outcome == VULNERABLE else "ok"
        print(f"{bf.probe.probe_id:40} {b_v:>10} {a_v:>10}")
    print("-" * 62)
    print(f"{'TOTAL vulnerable':40} {b['vulnerable']:>10} {a['vulnerable']:>10}")
    print(f"\nBaseline: {b['vulnerable']}/{b['total']} succeeded. "
          f"Hardened: {a['vulnerable']}/{a['total']} succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
