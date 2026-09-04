"""Offline report formats."""

from __future__ import annotations

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from . import __version__
from .model import Finding, Level
from .registry import INVENTORY
from .suppressions import dead_suppressions


def _summary(findings: list[Finding], suppressions: list[dict] | None, strict: bool) -> list[str]:
    if strict:
        return []
    suppressed = [finding for finding in findings if finding.suppression is not None]
    if not suppressed and not suppressions:
        return []
    entry_ids = {
        finding.suppression_entry
        if finding.suppression_entry is not None
        else ("reason", finding.suppression)
        for finding in suppressed
    }
    lines = [
        f"tf-nag: {len(suppressed)} findings suppressed by {len(entry_ids)} suppression entries"
    ]
    for item in dead_suppressions(suppressions or [], strict):
        lines.append(
            f"WARNING: suppression entry {item.get('_index', '?')} matched no findings "
            f"({item.get('id', item.get('rule'))}: {item['reason']})"
        )
    return lines


def render(
    findings: list[Finding],
    fmt: str = "table",
    suppressions: list[dict] | None = None,
    strict: bool = False,
) -> str:
    if fmt == "json":
        return json.dumps([f.as_dict() for f in findings], indent=2)
    if fmt == "sarif":
        rule_ids = sorted({finding.rule_id for finding in findings})
        rules = [
            {
                "id": rule_id,
                "shortDescription": {"text": INVENTORY.get(rule_id, {}).get("info", rule_id)},
                "fullDescription": {
                    "text": INVENTORY.get(rule_id, {}).get(
                        "explanation", INVENTORY.get(rule_id, {}).get("info", rule_id)
                    )
                },
            }
            for rule_id in rule_ids
        ]
        return json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "tf-nag",
                                "version": __version__,
                                "informationUri": (
                                    "https://dev.azure.com/access-devops/Access%20Vincere/"
                                    "_git/terraform-nag"
                                ),
                                "rules": rules,
                            }
                        },
                        "results": [
                            {
                                "ruleId": f.rule_id,
                                "level": "warning" if f.level == Level.WARN else "error",
                                "message": {"text": f.message},
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": f.address}}}
                                ],
                                **(
                                    {
                                        "suppressions": [
                                            {
                                                "kind": "external",
                                                "justification": f.suppression,
                                            }
                                        ]
                                    }
                                    if f.suppression
                                    else {}
                                ),
                            }
                            for f in findings
                        ],
                    }
                ],
            },
            indent=2,
        )
    if fmt == "junit":
        failures = sum(finding.suppression is None for finding in findings)
        suite = Element(
            "testsuite", name="tf-nag", tests=str(len(findings)), failures=str(failures)
        )
        for finding in findings:
            case = SubElement(suite, "testcase", name=f"{finding.rule_id} {finding.address}")
            if finding.suppression:
                skipped = SubElement(case, "skipped", message=finding.suppression)
                skipped.text = finding.suppression
            else:
                failure = SubElement(case, "failure", type=finding.level.value)
                failure.text = finding.message
        return tostring(suite, encoding="unicode")
    if fmt == "markdown":
        lines = ["| Level | Rule | Address | Message |", "|---|---|---|---|"]
        lines += [
            f"| {'SUPPRESSED' if f.suppression else f.level.value} | `{f.rule_id}` | "
            f"`{f.address}` | {f.message}"
            + (f" _(reason: {f.suppression})_" if f.suppression else "")
            + " |"
            for f in findings
        ]
        lines.extend(_summary(findings, suppressions, strict))
        return "\n".join(lines)
    if not findings:
        lines = ["tf-nag: no findings"]
        lines.extend(_summary(findings, suppressions, strict))
        return "\n".join(lines)
    lines = ["LEVEL       RULE              ADDRESS                         MESSAGE"]
    lines += [
        f"{'SUPPRESSED' if f.suppression else f.level.value:<10}  {f.rule_id:<16}  "
        f"{f.address:<30}  {f.message}" + (f" [reason: {f.suppression}]" if f.suppression else "")
        for f in findings
    ]
    lines.extend(_summary(findings, suppressions, strict))
    return "\n".join(lines)


def exit_code(findings: list[Finding], fail_on: str = "error") -> int:
    active = [finding for finding in findings if finding.suppression is None]
    errors = any(f.level == Level.ERROR for f in active)
    warns = any(f.level == Level.WARN for f in active)
    if fail_on == "never":
        return 0
    if errors and fail_on in ("error", "warn"):
        return 1
    if warns and fail_on == "warn":
        return 2
    return 0
