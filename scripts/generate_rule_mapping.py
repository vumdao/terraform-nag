"""Regenerate docs/rule-mapping.md from the vendored rule inventory."""

from pathlib import Path

from tfnag.registry import INVENTORY, discover, status


def main() -> None:
    discover()
    lines = [
        "# Rule mapping",
        "",
        "Generated from the vendored AWS Solutions inventory.",
        "",
        "| Rule | Level | Status | CloudFormation origin | Terraform coverage |",
        "|---|---|---|---|---|",
    ]
    for rule_id, item in sorted(INVENTORY.items()):
        origin = ", ".join(item.get("cfn", []))
        coverage = item.get("not_applicable_reason", "Implemented by tf-nag rules.")
        coverage = coverage.replace("|", "\\|")
        lines.append(
            f"| `{rule_id}` | {item['level']} | {status(rule_id)} | {origin} | {coverage} |"
        )
    Path("docs/rule-mapping.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
