"""Refresh the Lambda runtime table from the AWS supported-runtimes page.

`AwsSolutions-L1` needs the newest runtime per language family. The AWS docs
page is the only source that distinguishes generally available runtimes from
public-preview ones (the Lambda API enum lists both without a marker), and the
distinction matters: treating a preview runtime as "the latest" would make every
production function non-compliant.
"""

from __future__ import annotations

import re
from datetime import date

from .report import SyncReport

SOURCE_URL = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
SECTION_START = 'id="runtimes-supported"'
SECTION_END = 'id="runtimes-future"'
# Go and other compiled languages ship on the OS-only runtime, which the docs
# list under a name of its own rather than a language family.
OS_ONLY_FAMILY = "provided"
COMPILED_FAMILY = "go"
REQUIRED_FAMILIES = frozenset({"python", "nodejs", "java", "dotnet", "ruby", COMPILED_FAMILY})
_ROW = re.compile(r"<tr>(.*?)</tr>", re.S)
_CELL = re.compile(r"<td.*?>(.*?)</td>", re.S)
_TAG = re.compile(r"<[^>]+>")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9.]*$")
_FAMILY = re.compile(r"^[a-z]+")


def _text(html: str) -> str:
    return " ".join(_TAG.sub(" ", html).split())


def _version(identifier: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", identifier))


def _preview_names(section: str) -> list[str]:
    """Display names AWS calls out as public preview, e.g. ``Node.js 26``."""
    text = _text(section)
    names: list[str] = []
    for sentence in re.split(r"(?<=\.)\s", text):
        if "public preview" not in sentence.lower():
            continue
        names += re.findall(r"[A-Z][A-Za-z.]*(?:\.js)?\s\d+(?:\.\d+)?", sentence)
    return names


def parse_runtimes(html: str) -> tuple[dict, SyncReport]:
    """Build the ``lambda_runtimes.json`` payload from the docs page."""
    report = SyncReport(source="AWS Lambda supported runtimes")
    try:
        section = html[html.index(SECTION_START) : html.index(SECTION_END)]
    except ValueError as error:
        raise ValueError(f"supported-runtimes table not found on {SOURCE_URL}") from error

    preview_names = _preview_names(section)
    latest: dict[str, str] = {}
    preview: list[str] = []
    for row in _ROW.findall(section):
        cells = [_text(cell) for cell in _CELL.findall(row)]
        if len(cells) < 2 or not _IDENTIFIER.match(cells[1]):
            continue
        name, identifier = cells[0], cells[1]
        family = _FAMILY.match(identifier).group()
        if family == OS_ONLY_FAMILY:
            family = COMPILED_FAMILY
        if name in preview_names:
            preview.append(identifier)
            continue
        current = latest.get(family)
        if current is None or _version(identifier) > _version(current):
            latest[family] = identifier

    missing = REQUIRED_FAMILIES - latest.keys()
    if missing:
        raise ValueError(
            f"no supported runtime parsed for {sorted(missing)}; the docs layout probably changed"
        )
    for identifier in preview:
        family = _FAMILY.match(identifier).group()
        if _version(identifier) < _version(latest[family]):
            report.warnings.append(
                f"preview runtime `{identifier}` is older than the generally available "
                f"`{latest[family]}`, so it was kept but is redundant"
            )

    payload = {
        "source": SOURCE_URL,
        "fetched": date.today().isoformat(),
        "latest": {family: latest[family] for family in sorted(latest)},
        "preview": sorted(preview),
    }
    return payload, report


def diff(current: dict, payload: dict, report: SyncReport) -> dict:
    """Record runtime moves on ``report`` and keep ``fetched`` stable when nothing moved."""
    for family, identifier in payload["latest"].items():
        previous = current.get("latest", {}).get(family)
        if previous != identifier:
            report.changes.append(
                f"latest {family} runtime: `{previous or 'none'}` -> `{identifier}`"
            )
    for family in current.get("latest", {}):
        if family not in payload["latest"]:
            report.changes.append(f"{family} runtime family no longer listed by AWS")
    added = set(payload["preview"]) - set(current.get("preview", []))
    removed = set(current.get("preview", [])) - set(payload["preview"])
    for identifier in sorted(added):
        report.changes.append(f"preview runtime `{identifier}` is now accepted")
    for identifier in sorted(removed):
        report.changes.append(f"preview runtime `{identifier}` is no longer in preview")
    if not report.changes:
        payload["fetched"] = current.get("fetched", payload["fetched"])
    return payload
