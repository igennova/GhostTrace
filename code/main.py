"""GhostAudit entry point: read the dataset, audit every case, write output.csv.

Run from the repository root:

    python code/main.py

Wires the pipeline together: load the dataset, build the policy engine, build
(or load) the shared evidence index and the identity resolver, audit all
requests, then write and validate the repository-root ``output.csv``. Paths come
from arguments; nothing about specific cases or files is hardcoded.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as "python code/main.py" without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostaudit import agent, discovery, vision, writer  # noqa: E402
from ghostaudit.identity import IdentityResolver  # noqa: E402
from ghostaudit.llm import load_intent_classifier  # noqa: E402
from ghostaudit.loader import load_dataset  # noqa: E402
from ghostaudit.rules import RuleBook  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments (dataset dir, output path, cache control)."""
    parser = argparse.ArgumentParser(description="GhostAudit deletion-audit agent")
    parser.add_argument("--dataset", default=str(_REPO_ROOT / "dataset"),
                        help="path to the dataset/ directory")
    parser.add_argument("--output", default=str(_REPO_ROOT / "output.csv"),
                        help="path to write output.csv (repository root by default)")
    parser.add_argument("--rebuild-index", action="store_true",
                        help="force a rebuild of the evidence index cache")
    parser.add_argument("--no-vision", action="store_true",
                        help="skip PDF/image evidence extraction")
    return parser.parse_args(argv)


def run(dataset_dir: str | Path, output_path: str | Path,
        rebuild_index: bool = False, use_vision: bool = True) -> list[str]:
    """Execute the full audit pipeline, write output.csv, and validate it.

    Flow: ``load_dataset`` -> ``RuleBook`` + ``build_evidence_index`` +
    ``IdentityResolver`` -> ``agent.audit_all`` -> ``writer.write_output_csv``
    -> ``writer.validate_output``. Returns the list of validation problems
    (empty when the output is contract-valid).
    """
    dataset = load_dataset(dataset_dir)
    rules = RuleBook.from_dataset(dataset)
    index = discovery.build_evidence_index(dataset_dir, rebuild=rebuild_index)
    if use_vision:
        # PDF/screenshot records join the same index (VLM with a key, cached;
        # deterministic PDF text parsing without one).
        index, media = vision.augment_index(index, dataset)
        print("vision: {backend} ({model}) files={files} model_calls={model_calls} "
              "cached={cached} errors={errors} records={records}".format(**media))
    resolver = IdentityResolver.from_dataset(dataset)
    # LLM intent classification activates automatically when OPENAI_API_KEY is
    # set and the SDK is installed; otherwise the deterministic regex is used.
    intent_classifier = load_intent_classifier()
    print("intent: " + ("LLM (OpenAI)" if intent_classifier else "deterministic regex"))

    results = agent.audit_all(dataset, rules, index, resolver, intent_classifier)
    writer.write_output_csv(results, output_path)

    expected = [r.case_id for r in dataset.requests]
    return writer.validate_output(output_path, expected)


def main(argv: list[str] | None = None) -> int:
    """CLI main: parse args, run the pipeline, report, return an exit code."""
    args = parse_args(argv)
    problems = run(args.dataset, args.output, args.rebuild_index,
                   use_vision=not args.no_vision)
    if problems:
        print(f"output.csv FAILED validation ({len(problems)} problem(s)):")
        for p in problems[:20]:
            print(f"  - {p}")
        return 1
    print(f"output.csv written and validated: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
