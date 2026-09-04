"""Add upstream AWS Solutions explanations to the vendored inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _string(text: str, position: int) -> str:
    quote = text[position]
    position += 1
    result: list[str] = []
    escaped = False
    while position < len(text):
        char = text[position]
        position += 1
        if escaped:
            result.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            break
        else:
            result.append(char)
    return "".join(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="path to the upstream aws-solutions.ts file")
    source_path = parser.parse_args().source
    source = source_path.read_text(encoding="utf-8")
    explanations: dict[str, str] = {}
    marker = "ruleSuffixOverride:"
    position = 0
    while True:
        start = source.find(marker, position)
        if start < 0:
            break
        suffix_start = source.find("'", start + len(marker)) + 1
        suffix_end = source.find("'", suffix_start)
        suffix = source[suffix_start:suffix_end]
        next_marker = source.find(marker, suffix_end)
        block = source[suffix_end : next_marker if next_marker >= 0 else len(source)]
        explanation = block.find("explanation:")
        if explanation >= 0:
            absolute = suffix_end + explanation + len("explanation:")
            while source[absolute].isspace():
                absolute += 1
            if source[absolute] in "'\"`":
                explanations[suffix] = _string(source, absolute).replace("cdk-nag", "tf-nag")
        position = suffix_end

    path = Path("tfnag/data/aws_solutions_pack.json")
    inventory = json.loads(path.read_text())
    for item in inventory:
        if item["id"] in explanations:
            item["explanation"] = explanations[item["id"]]
    path.write_text(json.dumps(inventory, indent=2) + "\n")
    print(f"Added {len(explanations)} explanations.")


if __name__ == "__main__":
    main()
