"""Refresh the vendored AWS Solutions inventory from cdk-nag's pack source.

Upstream is TypeScript with no published machine-readable manifest, so the
``applyRule({...})`` blocks are scanned directly. Only the fields upstream owns
(``rule``, ``level``, ``info``, ``explanation``) are refreshed: ``cfn`` and the
``not_applicable_*`` fields are authored here and are preserved on merge.
"""

from __future__ import annotations

from .report import SyncReport

SOURCE_URL = (
    "https://raw.githubusercontent.com/cdklabs/cdk-nag/refs/heads/main/src/packs/aws-solutions.ts"
)
MARKER = "ruleSuffixOverride:"
UPSTREAM_FIELDS = ("rule", "level", "info", "explanation")
# The pack has had ~130 rules for years; a much smaller parse means upstream
# changed shape and the result must not be written over the vendored file.
MINIMUM_RULES = 100
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}


def _string(text: str, position: int) -> str:
    quote = text[position]
    position += 1
    result: list[str] = []
    escaped = False
    while position < len(text):
        char = text[position]
        position += 1
        if escaped:
            result.append(_ESCAPES.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            break
        else:
            result.append(char)
    return "".join(result)


def _field(block: str, name: str) -> str | None:
    marker = f"{name}:"
    position = 0
    while True:
        start = block.find(marker, position)
        if start < 0:
            return None
        # Skip "ruleSuffixOverride:" when looking for "rule:".
        if start > 0 and (block[start - 1].isalnum() or block[start - 1] in "_$"):
            position = start + len(marker)
            continue
        value = start + len(marker)
        while value < len(block) and block[value].isspace():
            value += 1
        if value >= len(block):
            return None
        if block[value] in "'\"`":
            return _string(block, value)
        end = value
        while end < len(block) and (block[end].isalnum() or block[end] in "._$"):
            end += 1
        return block[value:end]


def rebrand(text: str) -> str:
    return text.replace("cdk-nag", "tf-nag")


def parse_upstream(source: str, minimum: int = MINIMUM_RULES) -> dict[str, dict[str, str]]:
    """Extract ``{rule id suffix: {rule, level, info, explanation}}`` from the pack."""
    rules: dict[str, dict[str, str]] = {}
    position = 0
    while True:
        start = source.find(MARKER, position)
        if start < 0:
            break
        suffix_start = source.find("'", start + len(MARKER)) + 1
        suffix_end = source.find("'", suffix_start)
        suffix = source[suffix_start:suffix_end]
        next_marker = source.find(MARKER, suffix_end)
        block = source[suffix_end : next_marker if next_marker >= 0 else len(source)]
        level = _field(block, "level") or ""
        entry = {
            "rule": _field(block, "rule") or "",
            "level": level.rsplit(".", 1)[-1],
            "info": rebrand(_field(block, "info") or ""),
            "explanation": rebrand(_field(block, "explanation") or ""),
        }
        if suffix and all(entry.values()):
            rules[suffix] = entry
        position = suffix_end

    if len(rules) < minimum:
        raise ValueError(
            f"parsed only {len(rules)} rules from the AWS Solutions pack "
            f"(expected at least {minimum}); upstream layout probably changed"
        )
    return rules


def merge(
    inventory: list[dict], upstream: dict[str, dict[str, str]]
) -> tuple[list[dict], SyncReport]:
    """Apply upstream fields to the vendored inventory, preserving local ones."""
    report = SyncReport(source="cdk-nag AWS Solutions pack")
    merged = [dict(item) for item in inventory]
    by_id = {item["id"]: item for item in merged}

    for rule_id, entry in upstream.items():
        item = by_id.get(rule_id)
        if item is None:
            merged.append({"id": rule_id, "cfn": [], **entry})
            report.actions.append(
                f"`AwsSolutions-{rule_id}` ({entry['rule']}, {entry['level']}) is new upstream: "
                "it has no Terraform mapping yet and `tf-nag list-rules` reports it as "
                "not-implemented"
            )
            continue
        for field in UPSTREAM_FIELDS:
            if item.get(field) != entry[field]:
                report.changes.append(f"`AwsSolutions-{rule_id}`: {field} updated")
                item[field] = entry[field]

    for rule_id in by_id:
        if rule_id not in upstream:
            report.actions.append(
                f"`AwsSolutions-{rule_id}` no longer exists upstream: the vendored entry was "
                "kept, decide whether tf-nag should keep enforcing it"
            )

    return merged, report
