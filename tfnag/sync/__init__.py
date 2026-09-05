"""Refresh the data tf-nag vendors from upstream sources.

The rules themselves are offline, but three vendored artefacts describe things
AWS and cdk-nag own and therefore drift over time:

* ``tfnag/data/aws_solutions_pack.json`` - rule ids, levels and texts from
  cdk-nag's AWS Solutions pack.
* ``tfnag/data/lambda_runtimes.json`` - latest and preview Lambda runtimes.
* ``tfnag/data/provider_schema.json`` - pruned AWS provider schema snapshot.

Each syncer parses a source and returns the new content plus a human-readable
report; writing files and reporting drift is the caller's job (see
``scripts/sync_upstream.py``), which keeps every syncer testable offline.
"""

from .report import SyncReport

__all__ = ["SyncReport"]
