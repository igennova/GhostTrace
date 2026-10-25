# output.csv / steps_json — Reproduction Spec

Authoritative notes for reproducing the grader-visible output contract. Derived
from `problem_statement.md`, `README.md`, and empirical study of
`dataset/sample_output.csv` against `dataset/sample_deletion_requests.csv`.

## File-level contract

- Columns, in this exact order: `case_id,deletion_status,steps_json`.
- Exactly **518** data rows (one per `case_id` in `deletion_requests.csv`),
  plus the header. Rows **sorted by `case_id`**.
- `deletion_status` ∈ `COMPLETE` | `INCOMPLETE` | `NOT_APPLICABLE`.
- `steps_json` is a JSON **array** of step objects, stored as one CSV field
  (double-quoted; inner quotes escaped as `""`). It is **not** a delimiter-
  joined string — there is no separator to pick; it is serialized JSON.
- The grader parses `steps_json` as JSON. **Object-key order and whitespace are
  ignored; array order is significant.** (The samples prove this: `case_01`
  serializes keys alphabetically, `case_03` serializes them in logical order —
  both are accepted.)

## Step object — exactly these 7 fields

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

## Allowed operations (quoted from problem_statement.md)

| Phase | Operation | State | Meaning |
| --- | --- | --- | --- |
| `FINDING` | `REPORT_REMAINING_RECORD` | `PRESENT` | A record that should have been deleted still exists. |
| `FINDING` | `REPORT_EXPOSED_PII` | `PRESENT` | A record may remain, but it still contains identifiers that should have been redacted or anonymized. |
| `FINDING` | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | An active process can copy or recreate the user's data. |
| `FINDING` | `REPORT_RESTORE_RISK` | `ACTIVE` | A backup or restore path can bring deleted data back. |
| `REMEDIATION` | `DISABLE_DATA_FLOW` | `DISABLED` | Stop the process that can copy or recreate the data. |
| `REMEDIATION` | `BLOCK_RESTORE` | `BLOCKED` | Prevent the affected backup from restoring the user's data. |
| `REMEDIATION` | `DELETE_RECORD` | `ABSENT` | Remove the entire record. |
| `REMEDIATION` | `REDACT_RECORD` | `REDACTED` | Keep the record but remove the identifying fields required by policy. |
| `REMEDIATION` | `ANONYMIZE_RECORD` | `ANONYMIZED` | Keep the record after irreversibly unlinking it from the user. |
| `VERIFICATION` | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm that a record no longer exists. |
| `VERIFICATION` | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm that a policy-required retained record still exists. |
| `VERIFICATION` | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm that required identifying fields have been removed. |
| `VERIFICATION` | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm that the record can no longer be linked to the user. |
| `VERIFICATION` | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm that the relevant data flow is inactive. |
| `VERIFICATION` | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm that the affected data cannot be restored. |

**State is a pure function of operation** — each operation maps to exactly one
state (table above). Never invent phases, operations, or states.

## Ordering rules (apply in this precedence, then renumber)

1. **Phase:** `FINDING` → `REMEDIATION` → `VERIFICATION`.
2. **Operation:** within a phase, the order the operations appear in the table
   above (top-to-bottom). E.g. remediation is always
   `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`,
   `ANONYMIZE_RECORD` — i.e. recreation paths are stopped before copies change.
3. **`system_id`** ascending.
4. **`resource_id`** ascending.
5. **`step_no`** is assigned last: consecutive integers from `1` across the
   whole array in final order.

## evidence_id — filled vs empty

- **Findings** (any status) cite real evidence: a `file_id` (e.g.
  `evidence_54`), `activity_id`, or `audit_id` that proves the finding.
- **`COMPLETE` verification steps** cite real evidence proving the current
  compliant state at `audit_at`.
- **`INCOMPLETE` remediation and verification steps** describe future work, so
  `evidence_id` is the empty string `""`.

## Per-status shape

- **`NOT_APPLICABLE`** — request does not authorize deletion. `steps_json` is
  the empty array. Canonical form (from problem_statement.md; **no sample case
  demonstrates this** — all 32 samples authorize deletion):
  ```csv
  case_000,NOT_APPLICABLE,[]
  ```
- **`COMPLETE`** — **verification steps only**, each citing evidence. The set
  covers every record whose required final state must be proven: deleted
  account `VERIFY_RECORD_ABSENT`, retained security log `VERIFY_RECORD_PRESENT`,
  anonymized analytics `VERIFY_RECORD_ANONYMIZED`, redacted support/tombstone
  `VERIFY_RECORD_REDACTED`, disabled flow, blocked restore — as applicable.
- **`INCOMPLETE`** — `FINDING` steps (cite evidence) + the full `REMEDIATION`
  plan + the `VERIFICATION` checks that must pass after remediation (remediation
  and verification use empty `evidence_id`).

## Worked examples (from sample_output.csv)

### COMPLETE — `case_03` (3 steps, mixed treatments)
```
1 VERIFICATION account_service   account_7566       VERIFY_RECORD_ABSENT      ABSENT      evidence_94
2 VERIFICATION security_service  audit_record_2016  VERIFY_RECORD_PRESENT     PRESENT     evidence_94
3 VERIFICATION analytics_platform analytics_9406    VERIFY_RECORD_ANONYMIZED  ANONYMIZED  evidence_94
```
Pattern: only VERIFICATION; operation order ABSENT → PRESENT → ANONYMIZED
matches the table; every step cites the single snapshot (`evidence_94`) that
proves the state at `audit_at`.

### COMPLETE — `case_26` (6 steps, full verification set)
```
1 VERIFICATION account_service    account_5684      VERIFY_RECORD_ABSENT      ABSENT      evidence_92
2 VERIFICATION security_service   audit_record_5416 VERIFY_RECORD_PRESENT     PRESENT     evidence_92
3 VERIFICATION support_platform   support_4715      VERIFY_RECORD_REDACTED    REDACTED    evidence_92
4 VERIFICATION analytics_platform analytics_4566    VERIFY_RECORD_ANONYMIZED  ANONYMIZED  evidence_92
5 VERIFICATION integration_service data_flow_6244   VERIFY_DATA_FLOW_DISABLED DISABLED    evidence_92
6 VERIFICATION backup_service     backup_3120       VERIFY_RESTORE_BLOCKED    BLOCKED     evidence_92
```
Pattern: steps follow the VERIFICATION operation order exactly; all cite the
same `audit_at` snapshot.

### INCOMPLETE — `case_05` (minimal finding→fix→verify)
```
1 FINDING      account_service account_005 REPORT_REMAINING_RECORD PRESENT evidence_54
2 REMEDIATION  account_service account_005 DELETE_RECORD           ABSENT  ""
3 VERIFICATION account_service account_005 VERIFY_RECORD_ABSENT    ABSENT  ""
```
Pattern: finding cites evidence; remediation + verification have empty
`evidence_id`; one record carried through all three phases.

### INCOMPLETE — `case_11` (14 steps, all finding types + flow-first order)
```
FINDING:
 1 search_service      search_052       REPORT_REMAINING_RECORD  PRESENT evidence_03
 2 analytics_platform  analytics_2034   REPORT_EXPOSED_PII       PRESENT evidence_03
 3 support_platform    support_864      REPORT_EXPOSED_PII       PRESENT evidence_03
 4 integration_service data_flow_9522   REPORT_ACTIVE_DATA_FLOW  ACTIVE  evidence_03
REMEDIATION:
 5 integration_service data_flow_9522   DISABLE_DATA_FLOW        DISABLED ""
 6 search_service      search_052       DELETE_RECORD            ABSENT   ""
 7 support_platform    support_864      REDACT_RECORD            REDACTED ""
 8 analytics_platform  analytics_2034   ANONYMIZE_RECORD         ANONYMIZED ""
VERIFICATION:
 9 account_service     account_4248     VERIFY_RECORD_ABSENT     ABSENT   ""
10 search_service      search_052       VERIFY_RECORD_ABSENT     ABSENT   ""
11 security_service    audit_record_9394 VERIFY_RECORD_PRESENT   PRESENT  ""
12 support_platform    support_864      VERIFY_RECORD_REDACTED   REDACTED ""
13 analytics_platform  analytics_2034   VERIFY_RECORD_ANONYMIZED ANONYMIZED ""
14 integration_service data_flow_9522   VERIFY_DATA_FLOW_DISABLED DISABLED ""
```
Patterns confirmed:
- Finding operation order: REMAINING_RECORD → EXPOSED_PII → ACTIVE_DATA_FLOW.
- Within `REPORT_EXPOSED_PII` (steps 2–3), tie broken by `system_id`:
  `analytics_platform` < `support_platform`.
- Remediation stops the data flow (step 5) **before** cleaning dependent copies
  (6–8), matching the table operation order.
- Verification covers the deleted account (even though no account finding was
  raised), every remediated record, and the retained security log (PRESENT).
- All findings cite evidence; all remediation/verification `evidence_id` empty.

## Residual ambiguity to resolve during implementation

- **`resource_id` tie-break: numeric vs lexicographic.** The samples never place
  two steps with the *same operation and same system_id* differing only by
  `resource_id`, so the string-vs-numeric sort of the suffix is not empirically
  pinned. Plan: sort numerically on the integer suffix when the `prefix_<int>`
  shape holds, falling back to string compare; verify against the grader early.
