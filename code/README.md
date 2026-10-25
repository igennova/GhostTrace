# GhostAudit — Ghost Data Still Exists

An evidence-grounded deletion-audit agent. For every request in
`dataset/deletion_requests.csv`, it decides whether deletion was authorized,
reconstructs the subject's data state across all systems at the request's
`audit_at` cutoff, applies `dataset/deletion_rules.csv`, and emits an ordered
plan of findings, remediation, and verification steps to `output.csv`.

Deterministic core; an OpenAI model is used only for deletion-intent
classification and for reading PDF/screenshot evidence. Every model result is
cached on disk, so reruns make no new calls and the output is reproducible.

## Setup

```bash
cd code
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=...   # or put it in a repo-root .env; never commit it
```

Without a key the pipeline still runs: intent falls back to a deterministic
multilingual regex, PDFs are read with local text parsing, and screenshots are
used only if an earlier keyed run cached their extraction.

## Run

From the repository root:

```bash
python code/main.py               # full run (vision + LLM intent when keyed)
python code/main.py --no-vision   # skip PDF/image evidence
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
| `vision.py` | Read PDFs/screenshots into per-record observations (resource id, identifiers, explicit state); PDF values must appear verbatim in the text; merged into the shared index. |
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
