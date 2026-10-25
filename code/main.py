"""GhostAudit entry point: read the dataset, audit every case, write output.csv.

Run from the repository root:

    python code/main.py

Wires the pipeline modules together: load the dataset, build the policy engine
and the model client, audit all requests, then write and validate the
repository-root ``output.csv``. Paths and configuration come from arguments and
the environment; nothing about specific cases or files is hardcoded.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ghostaudit import agent, loader, rules, writer
from ghostaudit.llm import LLMConfig, load_llm_client


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments (dataset dir, output path, model config)."""
    raise NotImplementedError


def run(dataset_dir: str | Path, output_path: str | Path, config: LLMConfig) -> None:
    """Execute the full audit pipeline and write the output file.

    Flow: ``loader.load_dataset`` -> ``rules.load_rule_engine`` +
    ``load_llm_client`` -> ``agent.audit_all`` -> ``writer.write_output_csv``
    -> ``writer.validate_output``.
    """
    raise NotImplementedError


def main(argv: list[str] | None = None) -> int:
    """CLI main: parse args, run the pipeline, return a process exit code."""
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit(main())
