"""Command-line interface for tf-nag."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import scan
from .loader import PlanLoadError, load_plan
from .registry import INVENTORY, discover, status
from .reporters import exit_code, render
from .suppressions import (
    CONFIG_ERROR_EXIT,
    SuppressionConfigError,
    load_suppressions,
    suppression_path,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="tf-nag")
    result.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = result.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--plan-json", required=True)
    scan_parser.add_argument(
        "--format", choices=("table", "json", "sarif", "junit", "markdown"), default="table"
    )
    scan_parser.add_argument("--unknown-as", choices=("warn", "error", "ignore"), default="warn")
    scan_parser.add_argument("--fail-on", choices=("error", "warn", "never"), default="error")
    scan_parser.add_argument("--suppressions")
    scan_parser.add_argument("--strict", action="store_true")
    sub.add_parser("list-rules")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "list-rules":
        discover()
        print("RULE ID           LEVEL  STATUS          INFO")
        for rule_id, item in sorted(INVENTORY.items()):
            print(f"{rule_id:<17} {item['level']:<6} {status(rule_id):<15} {item['info']}")
        return 0
    try:
        suppressions = load_suppressions(suppression_path(args.suppressions))
    except SuppressionConfigError as exc:
        print(f"tf-nag: suppression configuration error: {exc}", file=sys.stderr)
        return CONFIG_ERROR_EXIT
    try:
        resources, configuration = load_plan(args.plan_json)
    except PlanLoadError as exc:
        print(f"tf-nag: {exc}", file=sys.stderr)
        return CONFIG_ERROR_EXIT
    findings = scan(resources, configuration, args.unknown_as, suppressions, args.strict)
    print(render(findings, args.format, suppressions, args.strict))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
