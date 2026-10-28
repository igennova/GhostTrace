# GhostTrace

**Find the personal data a "completed" deletion left behind.**

GhostTrace audits data-deletion requests. A deletion workflow can report
*Complete* while the person's data still sits in database replicas, logs,
support attachments, exports, search indexes, analytics, archives and backups,
or while an active sync or restore quietly puts it back. GhostTrace ignores
what the workflow *claims* and reconstructs what the evidence *shows*.

For each request it answers three questions:

1. **Did the person actually ask for deletion?** Access, export, correction and
   marketing opt-out requests are not deletions.
2. **Is the deletion really complete** at the audit time, under the company's
   retention policy?
3. **If not, what exactly remains, and how do you fix it safely?** It returns an
   ordered plan of findings, remediation steps and the checks that prove the fix.

Built for privacy and compliance teams, DPOs and auditors who need to show a
deletion happened, not just that a job said it did.

---

## How it works

**Deterministic core, models only at the edges.** Everything that decides a
verdict or a step is ordinary, testable code. A model is used for exactly two
jobs that code can't do well:

| Job | Model | Without an API key |
| --- | --- | --- |
| Does the request text authorize deletion? (any language) | `gpt-4o-mini`, temperature 0 | Multilingual keyword fallback |
| What records does a PDF or screenshot show? | `gpt-4o`, temperature 0 | PDFs parsed locally; screenshots skipped unless cached |

Every model result is validated before use and cached on disk, so a rerun makes
**zero** model calls and reproduces the output byte for byte.

```text
          request ──► intent check ──► not a deletion? ──► NOT_APPLICABLE
                           │
   email ──► identity (current + historical emails, phones, hashes, user id)
                           │
  evidence ──► discovery: SQL snapshots · JSON · logs · text · PDFs · screenshots
                           │       (only what existed at the audit time)
                           ▼
              every record of this person, with its state
                           │
        ┌──────────────────┼────────────────────┐
        ▼                  ▼                    ▼
   treatment          retention            recreation
 delete / redact /   keep required        active syncs,
 anonymize vs state  records; tombstone   restorable backups
                     keeps only user id
        └──────────────────┼────────────────────┘
                           ▼
          COMPLETE / INCOMPLETE  +  ordered plan  +  decision trace
```

### Principles

- **Claims are not proof.** Workflow statuses and activity-log results are
  claims. State comes from evidence: snapshots, readbacks, documents, screens.
- **State at a point in time.** Only evidence available at the audit cutoff
  counts, and only evidence captured after the request can show what happened
  after it. The latest authoritative observation of a record wins.
- **Absence must be proved.** A deleted account leaves nothing to match on, so
  GhostTrace links the account to the person and proves it is gone from a
  readback or a profile snapshot taken after the request.
- **Fail toward risk.** A sync or backup counts as able to recreate data unless
  the evidence shows it disabled or blocked.
- **Safe remediation order.** Stop data flows and block restores before
  touching the records they could recreate, and verify every end state.

---

## Quickstart

```bash
git clone https://github.com/igennova/GhostTrace.git
cd GhostTrace
python3 -m venv .venv && source .venv/bin/activate
pip install -r code/requirements.txt
cp .env.example .env          # optional: add OPENAI_API_KEY for intent + vision
```

```bash
python code/main.py                     # audit every request -> output.csv
python code/main.py --no-vision         # skip PDF / screenshot evidence
python -m pytest code/tests -q          # unit and adversarial tests
python code/evaluation/evaluate.py      # accuracy vs. labelled cases
python code/evaluation/usage_report.py  # model calls, tokens and cost
```

`main.py` validates its own output (row count, ordering, allowed operations
and states, step numbering, phase order) and prints how many model calls the
run made.

---

## Input and output

**Input** (`dataset/`):

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | `case_id, email, requested_at, reported_status, reported_at, audit_at, request_text` |
| `user_identities.csv`, `user_audit_log.csv` | Current identities and the history of email / phone / hash changes |
| `system_activity.csv` | Global stream of deletion, sync, export, backup, restore and catalog events |
| `deletion_rules.csv` | Required action per data category: delete, redact, anonymize, retain, tombstone |
| `evidence_files.csv` + `evidence/` | Manifest and files: SQL snapshots, JSON, logs, text, PDFs, screenshots |

**Output**: `output.csv` with `case_id, deletion_status, steps_json`, where
`deletion_status` is `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE`. Each step is:

```json
{"step_no": 1, "phase": "FINDING", "system_id": "account_service",
 "resource_id": "account_005", "operation": "REPORT_REMAINING_RECORD",
 "state": "PRESENT", "evidence_id": "evidence_54"}
```

Phases always run `FINDING → REMEDIATION → VERIFICATION`. Findings cite the
evidence that proves them; a complete case carries only evidence-backed
verification steps. Per-case reasoning (evidence used, why each step exists)
is written to `code/evaluation/decision_traces.jsonl`.

### Example

The workflow reported `account_005` deleted, and the activity log agrees
(deletion `SUCCESS`, replication checkpoint `SUCCESS`). A failover-replica
snapshot taken *after* that still holds the full profile. GhostTrace reports
the remaining record, plans its deletion, and adds the check that proves it's
gone: **INCOMPLETE**, where a log-trusting audit would have said complete.

---

## Results

On 32 labelled cases:

| Metric | Value |
| --- | --- |
| Verdict accuracy | **100% (32/32)** |
| Step precision / recall / F1 | 96.0% / 86.0% / 90.7% |
| Field-level accuracy | 80.7% |
| Exact step order | 43.8% (order similarity 82.9%) |

A full audit of 518 requests from an empty cache took 390 model calls
(375 intent, 15 vision), 171k tokens and about **$0.12** in total, roughly
$0.0002 per request. Warm reruns make no calls.

Full breakdowns: [`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md)
and [`code/evaluation/usage_report.md`](code/evaluation/usage_report.md).

---

## Project structure

```text
code/
  main.py                 CLI: run the audit, validate, write output + traces
  ghostaudit/
    loader.py             load CSVs and the evidence manifest
    identity.py           current + historical identifiers for a person
    discovery.py          parse text evidence into a shared, cached index
    vision.py             PDF / screenshot records (model-assisted, verified)
    accounts.py           link deleted accounts and prove their absence
    rules.py              policy per data category
    treatment.py          compare each record's state with its required action
    retention.py          records that must be kept; tombstone rules
    recreation.py         active syncs and restorable backups
    status.py             verdict + deletion-intent fallback
    remediation.py        ordered findings, fixes and checks
    writer.py             output schema, ordering, validation
    llm.py                intent classifier (cached, usage-logged)
    agent.py              one audit per request, with its decision trace
  prompts/                versioned model prompts
  evaluation/             evaluator, reports, decision traces
  tests/                  unit and adversarial tests
dataset/                  inputs (see above)
docs/output_spec.md       detailed output format
```

---

## Limitations

- **Ambiguous account links.** When several requests share a reporting window
  and their deletion events look identical, the account link is a
  deterministic tie-break and can be wrong.
- **Silence can look clean.** A missed record produces no finding. A planned
  change is to require positive proof per system before calling a case
  complete, and to send gaps to review instead.
- **Legal-hold expiry isn't evaluated yet.** Holds are always treated as
  active; expired holds should fall back to the category's normal treatment.
- **Identifier ownership isn't time-scoped.** A recycled email could match the
  previous owner's later records; ownership windows from the audit log would
  close this.
- **Keyless mode is a draft.** The keyword fallback over-triggers on words like
  "cancel" or "close", and screenshots are skipped unless cached.

## Security

- API keys are read from the environment or an uncommitted `.env` only.
- Evidence content is treated as untrusted data; the vision prompt forbids
  following instructions embedded in documents or screens.
- Decision traces record which *kind* of identifier matched, never its value.
