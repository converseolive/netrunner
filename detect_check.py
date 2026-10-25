#!/usr/bin/env python3
"""
NetRunner OS - Headless detection validation (CLI).

Runs the same ExtraHop detection correlation as the web UI, using the saved
settings (data/settings.json) and persisted run history (data/runs.json), then
prints a summary + per-scenario scorecard and optionally writes the HTML report.
Useful for scheduled lab validation (e.g. a nightly generate-then-check run).

Run from the repo root so the `app` package is importable:

    python3 detect_check.py
    python3 detect_check.py --report run-report.html
    python3 detect_check.py --json

When no appliance is configured it prints a clearly-labelled sample result, so
you can see the shape of the output before wiring up the lab.
"""
import argparse
import json
import sys


def _print_summary(result):
    s = result.get('summary', {})
    print("=" * 56)
    print("EXTRAHOP DETECTION VALIDATION")
    print("=" * 56)
    note = result.get('note')
    if result.get('sample'):
        print("  (sample data - no appliance configured in Settings)")
    elif note == 'no_runs':
        print("  No runs recorded yet - generate traffic first.")
    if result.get('error'):
        print(f"  Appliance error: {result['error']}")

    rate = round((s.get('detection_rate') or 0) * 100)
    ttd = s.get('mean_ttd_ms')
    print(f"  Detection rate : {rate}%")
    print(f"  Detected       : {s.get('detected', 0)}/{s.get('total', 0)}")
    print(f"  Partial        : {s.get('partial', 0)}")
    print(f"  Missed         : {s.get('missed', 0)}")
    print(f"  Mean TTD       : {round(ttd / 1000)}s" if ttd else "  Mean TTD       : -")

    rows = result.get('rows', [])
    if rows:
        print("\n  Scenario                Status     ExtraHop detection")
        print("  " + "-" * 54)
        for r in rows:
            name = (r.get('name') or '')[:22]
            status = r.get('status', '')
            det = r.get('detection') or '-'
            print(f"  {name:<23} {status:<10} {det}")


def main():
    parser = argparse.ArgumentParser(description="NetRunner ExtraHop detection validation")
    parser.add_argument("--report", metavar="PATH",
                        help="write the HTML validation report to this file")
    parser.add_argument("--json", action="store_true",
                        help="emit the raw result as JSON instead of a summary")
    args = parser.parse_args()

    try:
        from app.core import validation, report
    except ImportError as e:
        print(f"[FAIL] Could not import NetRunner: {e}")
        print("       Run from the repo root with dependencies installed.")
        return 1

    result = validation.run_validation()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_summary(result)

    if args.report:
        try:
            with open(args.report, "w") as f:
                f.write(report.build_report_html(result))
            print(f"\n[+] Wrote report to {args.report}")
        except IOError as e:
            print(f"\n[FAIL] Could not write {args.report}: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
