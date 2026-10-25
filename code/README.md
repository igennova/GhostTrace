# GhostAudit — Ghost Data Still Exists

An evidence-grounded deletion-audit agent. For every request in
`dataset/deletion_requests.csv` it decides whether the person actually asked
for deletion, reconstructs their data across every system **as of the
request's `audit_at`**, applies `dataset/deletion_rules.csv`, and writes an
ordered plan of findings → remediation → verification to `output.csv`.

Workflow statuses and activity results are treated as **claims**; state is
established only from evidence available at the cutoff.

## Approach

**Deterministic core, models only at the boundaries.** Two narrow jobs need a
model; everything that decides a status or a step is ordinary code:

| Job | Model | Why a model | Without a key |
| --- | --- | --- | --- |
| Does the request authorize deletion? | `gpt-4o-mini` (temp 0) | Free text in many languages; access/export/opt-out requests look similar | Multilingual regex |
| What records does a PDF / screenshot show? | `gpt-4o` (temp 0) | Evidence includes console screenshots and documents | PDFs parsed locally (pypdf); screenshots skipped unless cached |

Every model result is cached on disk (intent by model + prompt version +
text; vision by file content hash + prompt version) and validated before use,
so a rerun makes **zero** model calls and reproduces `output.csv` byte for
byte. We rejected an LLM tool-loop agent: discovery is already exhaustive over
a fixed corpus, so a loop would add cost and drift without adding capability.

## Architecture

```text
                     dataset/*.csv            dataset/evidence/**
                          │                     │            │
                       loader              text files    PDF / PNG
                          │            (SQL, JSON, logs)      │
                          ▼                     │       ┌─────┴──────┐
   request_text ──► intent (LLM │ regex)        │       │ vision.py  │  gpt-4o, cached,
                          │                     ▼       │ per-record │  verified
                    NOT_APPLICABLE?      discovery.py ◄─┤ + catalog  │
                          │              shared index   │  aliases   │
   email ──► identity.py (current +            │        └────────────┘
             historical identifiers,           │
             email hash, user_id)              │
                          └──────────► records at audit_at ◄── accounts.py
                                               │               (link account,
                                               │                prove ABSENT)
                       ┌───────────────────────┼───────────────────────┐
                       ▼                       ▼                       ▼
                  treatment.py           retention.py            recreation.py
               (DELETE/REDACT/        (RETAIN, tombstone      (active flows,
                ANONYMIZE vs state)    keeps only user_id)     restorable backups)
                       └───────────────────────┼───────────────────────┘
                                               ▼
                               status.py ── COMPLETE / INCOMPLETE
                                               ▼
                            remediation.py ─► writer.py ─► output.csv
                                               └─► decision_traces.jsonl
```

| Module | Responsibility |
| --- | --- |
| `loader.py` | Read every CSV and the evidence manifest into a `Dataset`. |
| `identity.py` | Resolve current and historical emails/phones (audit log), `user_id`, `sha256(email)`. |
| `discovery.py` | Parse all text evidence once (SQL via in-memory SQLite, JSON, logs, text) into a cached index; match by identifier tokens and resource-id links; keep only observations available at `audit_at`. |
| `vision.py` | Read PDFs/screenshots into per-record observations: internal id or printed reference (resolved through the data catalog), identifiers, explicit state. PDF values must appear verbatim in the text. |
| `accounts.py` | Link each subject to its `account_service` resource and, when the account is gone, ground `ABSENT` in its readback or the latest profile snapshot at `audit_at`. |
| `rules.py` | Required action and permitted identifiers per data category. |
| `treatment.py` | Compare each record's state at the cutoff with its required action. |
| `retention.py` | Must-retain records are present; tombstones keep only the stable reference. |
| `recreation.py` | Active sync/export flows and restorable backups (evidence first, activity claims otherwise). |
| `status.py` | COMPLETE only if every copy is treated, retained records are intact, and nothing can recreate the data. |
| `remediation.py` / `writer.py` | Ordered FINDING → REMEDIATION → VERIFICATION steps, numbering, serialization, contract validation. |
| `llm.py` | Intent classifier (strict JSON, cached, usage-logged). |
| `agent.py` | One bounded audit per case, plus its decision trace. |

### Key decisions

- **State at `audit_at`.** An observation counts only if both its own timestamp
  and its evidence file's capture time are at or before the cutoff; the latest
  authoritative observation per resource wins, so a later readback overrides
  an earlier "deleted" claim.
- **Deleted accounts.** A deleted account has no row carrying the subject's
  identifiers. It is linked through evidence, or through the deletion
  workflow's own `DELETE_RECORD` event near `reported_at` (one account per
  request across all requests), and its absence is proved from a readback or
  snapshot, never from the event's claimed result.
- **Media is evidence, not a verdict.** Screens and documents yield records
  that join the same index as text evidence. Backup/connector rows decide
  flow/restore state only when the screen shows an explicit flag.
- **Remediation order.** Disable flows and block restores before changing
  dependent records; verification covers the required end state of every
  remediated record or process.

## Setup

`code.zip` holds the contents of this `code/` folder: unzip it into `code/`
at the repository root, next to `dataset/`.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r code/requirements.txt
export OPENAI_API_KEY=...   # or put it in a repo-root .env; never commit it
```

Without a key the pipeline still runs: intent uses the regex, PDFs are read
locally, and screenshots are used only if an earlier keyed run cached them.

## Run

From the repository root (with `dataset/` present):

```bash
python code/main.py                     # writes ./output.csv and decision traces
python code/main.py --no-vision         # skip PDF/image evidence
python -m pytest code/tests -q          # unit + adversarial tests
python code/evaluation/evaluate.py      # sample-set accuracy -> evaluation_report.md
python code/evaluation/usage_report.py  # usage_report.md from the logged calls
```

`main.py` validates `output.csv` against the contract (518 rows, sorted,
allowed phases/operations/states, consecutive numbering, phase order) and
prints the number of model calls the run made. Per-case decision traces go to
`code/evaluation/decision_traces.jsonl`.

## Results

Public sample set (32 cases with reference answers, `evaluation/evaluate.py`):

| Metric | Value |
| --- | --- |
| Case-level status accuracy | **100% (32/32)** |
| Step set precision / recall / F1 | 96.0% / 86.0% / 90.7% |
| Field-level accuracy (position-aligned) | 80.7% |
| Sequence accuracy (exact order) | 43.8% (14/32); mean order similarity 82.9% |
| Authored edge cases | 3/3 pass |

Evaluation set (`output.csv`): 518 rows, contract-valid — 325 INCOMPLETE,
183 COMPLETE, 10 NOT_APPLICABLE; 2,627 steps.

Final full run from an empty cache: 390 model calls (375 intent with
`gpt-4o-mini`, 15 vision with `gpt-4o`), 171,111 tokens, about $0.12 in total
(≈ $0.0002 per request). Warm reruns make 0 calls and reproduce `output.csv`
byte for byte.

Details: [`evaluation/evaluation_report.md`](evaluation/evaluation_report.md)
(per-case diffs, three authored edge cases, failures found and fixed) and
[`evaluation/usage_report.md`](evaluation/usage_report.md) (model calls,
tokens, cost).

## Known limitations

- **Ambiguous account links.** When several requests share a reporting window
  and their deletion events carry the same result, the account link is a
  deterministic tie-break and can pick the wrong account (sample `case_23`).
- **Accounts with no trace.** An account absent from all evidence and activity
  cannot be linked, so its verification step is missing (sample `case_04`).
- **Order within a phase.** Most remaining sample mismatches are step order or
  an extra/missing secondary record rather than a wrong status.
- **Media cache is local.** Screenshot extractions live in the gitignored
  `.cache/`; a fresh keyless clone skips screenshots until a keyed run.
- **Model variance on a cold cache.** `gpt-4o` at temperature 0 can label a
  screen slightly differently between cold runs; validation and the rules above
  absorb this (two independent extractions gave byte-identical output), but a
  different cache can in principle change a borderline case.
- **Evidence before the request.** State is established only from evidence
  captured at or after `requested_at`; earlier evidence links identities but
  never decides a record's state.

## Compliance notes

- Only participant-facing files under `dataset/` are read; no organizer files,
  golden labels, or case-specific shortcuts.
- Secrets come from the environment (or an uncommitted `.env`) only.
- Evidence text is treated as untrusted data; the vision prompt forbids
  following instructions embedded in documents.
