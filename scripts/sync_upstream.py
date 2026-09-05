"""Refresh every vendored upstream artefact and report what drifted.

Run by `azure-pipelines/upstream-sync.yml` weekly; also useful by hand:

    python scripts/sync_upstream.py --summary-out sync-summary.md

Sources can be replaced with local files (`--pack-file`, `--runtimes-file`,
`--schema-file`) to run without network access.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tfnag.registry import RULES, discover  # noqa: E402
from tfnag.schema import validate_rule_metadata  # noqa: E402
from tfnag.sync import pack, provider, runtimes  # noqa: E402
from tfnag.sync import report as report_module  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "tfnag" / "data"
PACK_PATH = DATA / "aws_solutions_pack.json"
RUNTIMES_PATH = DATA / "lambda_runtimes.json"
SCHEMA_PATH = DATA / "provider_schema.json"
TIMEOUT = 60
PROVIDER_CONFIG = """terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
"""


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "tf-nag-upstream-sync"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return response.read().decode("utf-8")


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def sync_pack(source: str) -> report_module.SyncReport:
    merged, report = pack.merge(read_json(PACK_PATH), pack.parse_upstream(source))
    if report.drifted:
        write_json(PACK_PATH, merged)
    return report


def sync_runtimes(source: str) -> report_module.SyncReport:
    payload, report = runtimes.parse_runtimes(source)
    payload = runtimes.diff(read_json(RUNTIMES_PATH), payload, report)
    if report.drifted:
        write_json(RUNTIMES_PATH, payload)
    return report


def terraform_schema() -> dict:
    """Full provider schema, produced by initialising the latest AWS provider."""
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        (workspace / "providers.tf").write_text(PROVIDER_CONFIG, encoding="utf-8")
        subprocess.run(
            ["terraform", "init", "-input=false", "-no-color"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        )
        completed = subprocess.run(
            ["terraform", "providers", "schema", "-json"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        )
    return json.loads(completed.stdout)


def sync_schema(schema: dict) -> report_module.SyncReport:
    discover()
    current = read_json(SCHEMA_PATH)
    pruned = provider.prune(schema, provider.wanted_resource_types(RULES))
    report = provider.diff(current, pruned)
    if report.drifted:
        write_json(SCHEMA_PATH, pruned)
        # A rule whose attribute path the provider dropped keeps scanning plans but no
        # longer matches anything, so it needs remapping by hand.
        report.actions += [
            f"rule metadata no longer matches the provider: {error}"
            for error in validate_rule_metadata(RULES)
        ]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-file", type=Path, help="local copy of aws-solutions.ts")
    parser.add_argument("--runtimes-file", type=Path, help="local copy of the AWS runtimes page")
    parser.add_argument(
        "--schema-file", type=Path, help="local terraform providers schema -json output"
    )
    parser.add_argument(
        "--skip-schema", action="store_true", help="leave the provider schema snapshot untouched"
    )
    parser.add_argument("--summary-out", type=Path, help="write the Markdown summary here")
    args = parser.parse_args()

    pack_source = (
        args.pack_file.read_text(encoding="utf-8") if args.pack_file else fetch(pack.SOURCE_URL)
    )
    runtimes_source = (
        args.runtimes_file.read_text(encoding="utf-8")
        if args.runtimes_file
        else fetch(runtimes.SOURCE_URL)
    )

    reports = [sync_pack(pack_source), sync_runtimes(runtimes_source)]
    if not args.skip_schema:
        schema = read_json(args.schema_file) if args.schema_file else terraform_schema()
        reports.append(sync_schema(schema))

    summary = report_module.markdown(reports)
    if args.summary_out:
        args.summary_out.write_text(summary + "\n", encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
