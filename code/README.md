# GhostAudit — Ghost Data Still Exists

An evidence-grounded deletion-audit agent. For every request in
`dataset/deletion_requests.csv`, it decides whether deletion was authorized,
reconstructs the subject's data state across all systems at the request's
`audit_at` cutoff, applies `dataset/deletion_rules.csv`, and emits an ordered
plan of findings, remediation, and verification steps to `output.csv`.

> Status: **scaffold**. Modules define responsibilities and signatures; logic
> is not yet implemented.

## Setup

```bash
cd code
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...   # read from the environment only; never commit
```

## Run

From the repository root:

```bash
python code/main.py
```

Writes the final `output.csv` (header `case_id,deletion_status,steps_json`,
one row per case, sorted by `case_id`) to the repository root.

## Architecture

The pipeline is a chain of single-responsibility modules under
`ghostaudit/`, orchestrated per request by `agent.py`:

| Module | Responsibility |
| --- | --- |
| `loader.py` | Read all CSVs and locate evidence media into a `Dataset`. |
| `identity.py` | Resolve current + historical identifiers for the subject. |
| `discovery.py` | Find subject-matching records at/before `audit_at`. |
| `accounts.py` | Link each subject to its account (evidence, else the workflow's own delete event) and synthesize ABSENT from the latest profile snapshot at `audit_at`. |
| `rules.py` | Map data category + condition to required treatment. |
| `treatment.py` | Check each copy: deleted / redacted / anonymized / exposed. |
| `recreation.py` | Detect active sync and restore paths that recreate data. |
| `retention.py` | Records that must be kept and identifiers they may keep. |
| `remediation.py` | Build ordered findings → remediation → verification steps. |
| `status.py` | Decide COMPLETE / INCOMPLETE / NOT_APPLICABLE. |
| `vision.py` | Extract identifiers/facts from images and PDFs. |
| `llm.py` | Structured model calls for messy text and media only. |
| `writer.py` | Own the output schema: ordering, serialization, validation. |
| `agent.py` | Wire the modules into one bounded audit per case. |

Evaluation lives in `evaluation/` (`evaluate.py`, `report.py`), versioned
prompts in `prompts/`, and tests in `tests/`.

## Data flow

See the top-level response / the module docstrings. In short: loader →
identity → discovery (+ vision) → rules → treatment + recreation + retention →
status + remediation → writer.

## Notes

- Reported workflow statuses and operation results are treated as claims; the
  true state is established from evidence at `audit_at`.
- Only participant-facing files under `dataset/` are used.
- Secrets are read from environment variables only.
