"""Drift report shared by the syncers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SyncReport:
    """What a syncer changed, and what a human still has to do about it."""

    source: str
    changes: list[str] = field(default_factory=list)
    # Drift a human must act on, e.g. a rule id cdk-nag added or removed.
    actions: list[str] = field(default_factory=list)
    # Anything the syncer could not verify, e.g. a cross-check disagreement.
    warnings: list[str] = field(default_factory=list)

    @property
    def drifted(self) -> bool:
        return bool(self.changes or self.actions)

    def markdown(self) -> str:
        lines = [f"### {self.source}", ""]
        if not self.drifted and not self.warnings:
            lines += ["No changes.", ""]
            return "\n".join(lines)
        for title, items in (
            ("Action required", self.actions),
            ("Changes", self.changes),
            ("Warnings", self.warnings),
        ):
            if items:
                lines.append(f"**{title}**")
                lines += [f"- {item}" for item in items]
                lines.append("")
        return "\n".join(lines)


def markdown(reports: list[SyncReport]) -> str:
    """Render a PR-ready summary of every syncer that ran."""
    header = ["## Upstream sync", ""]
    actions = [action for report in reports for action in report.actions]
    if actions:
        header += [
            "Needs a human: upstream rule membership changed, see **Action required** below.",
            "",
        ]
    return "\n".join(header + [report.markdown() for report in reports])
