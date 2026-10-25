"""Scoring: run the agent on cases with expected output and compare.

Runs the deletion-audit agent on the public sample requests
(``sample_deletion_requests.csv``) and compares the predictions to the known
answers (``sample_output.csv``):

- ``deletion_status``: exact match (case-level accuracy);
- discovered records / resources: compared as SETS (precision / recall / F1);
- ``steps_json``: step-set precision/recall/F1, field-level accuracy, and
  sequence (order) accuracy, with a readable diff for every mismatch.

It also runs three hand-built edge cases owned by this project, then writes
``code/evaluation/evaluation_report.md`` and prints it. Deterministic; it uses
the regex intent fallback unless an OpenAI key is configured.
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_CODE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CODE_DIR))
_REPO_ROOT = _CODE_DIR.parent

from ghostaudit import (  # noqa: E402
    accounts, agent, discovery, recreation, remediation, retention, status,
    treatment,
)
from ghostaudit.discovery import DiscoveredRecord  # noqa: E402
from ghostaudit.identity import IdentityResolver  # noqa: E402
from ghostaudit.loader import Dataset, load_dataset, load_requests  # noqa: E402
from ghostaudit.llm import load_intent_classifier  # noqa: E402
from ghostaudit.rules import RuleBook  # noqa: E402
from ghostaudit.writer import Step, order_steps  # noqa: E402

_SIG_FIELDS = ("phase", "system_id", "resource_id", "operation", "state")


# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------
def _step_dict(step: Step) -> dict:
    return {
        "step_no": step.step_no, "phase": step.phase, "system_id": step.system_id,
        "resource_id": step.resource_id, "operation": step.operation,
        "state": step.state, "evidence_id": step.evidence_id,
    }


def _sig(s: dict) -> tuple:
    return tuple(s[f] for f in _SIG_FIELDS)


def _resources(steps: list[dict]) -> set[tuple[str, str]]:
    return {(s["system_id"], s["resource_id"]) for s in steps}


def _lcs_len(a: list, b: list) -> int:
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    return dp[0][0]


@dataclass
class CaseScore:
    case_id: str
    expected_status: str
    predicted_status: str
    status_correct: bool
    res_tp: int = 0
    res_fp: int = 0
    res_fn: int = 0
    step_tp: int = 0
    step_fp: int = 0
    step_fn: int = 0
    field_matches: int = 0
    field_total: int = 0
    sequence_exact: bool = False
    seq_lcs: float = 0.0
    diff: str = ""


def compare_case(case_id: str, pred_status: str, pred_steps: list[dict],
                 exp_status: str, exp_steps: list[dict]) -> CaseScore:
    sc = CaseScore(case_id, exp_status, pred_status, pred_status == exp_status)

    pr, er = _resources(pred_steps), _resources(exp_steps)
    sc.res_tp, sc.res_fp, sc.res_fn = len(pr & er), len(pr - er), len(er - pr)

    ps, es = [_sig(s) for s in pred_steps], [_sig(s) for s in exp_steps]
    pset, eset = set(ps), set(es)
    sc.step_tp, sc.step_fp, sc.step_fn = len(pset & eset), len(pset - eset), len(eset - pset)

    # Field-level accuracy: position-aligned over the longer list, 6 compared
    # fields per step (evidence compared as present/absent to allow any valid
    # proving evidence id). step_no is implied by position.
    n = max(len(pred_steps), len(exp_steps))
    cmp_fields = _SIG_FIELDS + ("evidence_present",)
    for i in range(n):
        p = pred_steps[i] if i < len(pred_steps) else None
        e = exp_steps[i] if i < len(exp_steps) else None
        for f in cmp_fields:
            sc.field_total += 1
            if p is None or e is None:
                continue
            pv = bool(p["evidence_id"]) if f == "evidence_present" else p[f]
            ev = bool(e["evidence_id"]) if f == "evidence_present" else e[f]
            if pv == ev:
                sc.field_matches += 1

    sc.sequence_exact = ps == es
    sc.seq_lcs = (_lcs_len(ps, es) / max(len(es), 1)) if es else (1.0 if not ps else 0.0)

    if not sc.status_correct or pset != eset or not sc.sequence_exact:
        sc.diff = _render_diff(pred_steps, exp_steps)
    return sc


def _render_diff(pred_steps: list[dict], exp_steps: list[dict]) -> str:
    def fmt(s):
        ev = s["evidence_id"] or "-"
        return f"{s['phase'][:4]:<4} {s['operation']:<24} {s['system_id']}/{s['resource_id']} [{s['state']}] ev={ev}"
    lines = ["    expected:" if exp_steps else "    expected: (none)"]
    lines += [f"      {i+1:>2} {fmt(s)}" for i, s in enumerate(exp_steps)]
    lines += ["    predicted:" if pred_steps else "    predicted: (none)"]
    lines += [f"      {i+1:>2} {fmt(s)}" for i, s in enumerate(pred_steps)]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sample run
# ---------------------------------------------------------------------------
@dataclass
class Aggregate:
    scores: list[CaseScore] = field(default_factory=list)

    def _rate(self, num, den):
        return num / den if den else 0.0

    def status_accuracy(self):
        return self._rate(sum(s.status_correct for s in self.scores), len(self.scores))

    def _prf(self, tp_attr, fp_attr, fn_attr):
        tp = sum(getattr(s, tp_attr) for s in self.scores)
        fp = sum(getattr(s, fp_attr) for s in self.scores)
        fn = sum(getattr(s, fn_attr) for s in self.scores)
        p = self._rate(tp, tp + fp); r = self._rate(tp, tp + fn)
        f1 = self._rate(2 * p * r, p + r) if (p + r) else 0.0
        return p, r, f1

    def resource_prf(self):
        return self._prf("res_tp", "res_fp", "res_fn")

    def step_prf(self):
        return self._prf("step_tp", "step_fp", "step_fn")

    def field_accuracy(self):
        return self._rate(sum(s.field_matches for s in self.scores),
                          sum(s.field_total for s in self.scores))

    def sequence_accuracy(self):
        return self._rate(sum(s.sequence_exact for s in self.scores), len(self.scores))

    def mean_lcs(self):
        return self._rate(sum(s.seq_lcs for s in self.scores), len(self.scores))


def evaluate(dataset_dir: str | Path, sample_requests: str | Path,
             expected_csv: str | Path) -> tuple[Aggregate, list[CaseScore]]:
    dataset = load_dataset(dataset_dir)
    rules = RuleBook.from_dataset(dataset)
    index = discovery.build_evidence_index(dataset_dir)
    resolver = IdentityResolver.from_dataset(dataset)
    classifier = load_intent_classifier()
    account_context = accounts.AccountContext.build(dataset, index, resolver)

    requests = load_requests(sample_requests)
    expected = _load_expected(expected_csv)

    agg = Aggregate()
    for req in requests:
        result = agent.audit_case(req, dataset, rules, index, resolver, classifier,
                                  account_context)
        pred_steps = [_step_dict(s) for s in order_steps(list(result.steps))]
        exp = expected.get(req.case_id, {"status": "", "steps": []})
        agg.scores.append(compare_case(
            req.case_id, result.deletion_status, pred_steps,
            exp["status"], exp["steps"]))
    return agg, agg.scores


def _load_expected(path: str | Path) -> dict:
    out = {}
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            steps = json.loads(row["steps_json"])
            steps.sort(key=lambda s: s["step_no"])
            out[row["case_id"]] = {"status": row["deletion_status"], "steps": steps}
    return out


# ---------------------------------------------------------------------------
# Hand-built edge cases owned by this project
# ---------------------------------------------------------------------------
def _rec(system, resource, category, state, ids=None):
    return DiscoveredRecord(
        system_id=system, resource_id=resource, data_category=category,
        observed_state=state, observed_at="2026-09-01T00:00:00Z",
        evidence_id="evidence_x", identifiers=ids or {"email": "e@x.com"},
        matched_on=["e@x.com"], table_or_collection="handover",
    )


class _StubId:
    def match_keys(self):
        return set()


def _run_synthetic(records, request_text, rules) -> tuple[str, list[dict]]:
    treatments = treatment.assess_treatments(records, rules)
    retentions = retention.assess_retention(records, rules)
    risks = recreation.detect_recreation(records, Dataset(dataset_dir=Path(".")),
                                         _StubId(), "2026-10-01T00:00:00Z")
    authorized = status.is_authorized_deletion(request_text)
    decision = status.decide_status(authorized, treatments, retentions, risks)
    steps = [_step_dict(s) for s in remediation.build_steps(
        decision, treatments, retentions, risks)]
    return decision, steps


def custom_cases(rules: RuleBook):
    """Three owned edge cases: (status, pred_steps, expected_sigs)."""
    cases = []

    # Case 1: account tombstone still exposing email -> INCOMPLETE (redact).
    recs = [
        _rec("account_service", "account_1", "USER_PROFILE", "ABSENT"),
        _rec("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "PRESENT",
             {"subject_reference": "user_1"}),
        _rec("identity_service", "tombstone_1", "ACCOUNT_TOMBSTONE", "EXPOSED",
             {"subject_reference": "user_1", "email": "e@x.com"}),
    ]
    status1, steps1 = _run_synthetic(recs, "Please delete my account.", rules)
    expected1 = [
        ("FINDING", "identity_service", "tombstone_1", "REPORT_EXPOSED_PII", "PRESENT"),
        ("REMEDIATION", "identity_service", "tombstone_1", "REDACT_RECORD", "REDACTED"),
        ("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFICATION", "security_service", "audit_record_1", "VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFICATION", "identity_service", "tombstone_1", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ]
    cases.append(("tombstone_exposed_email", "INCOMPLETE", status1, steps1, expected1))

    # Case 2: account deleted but active sync + restorable backup -> INCOMPLETE.
    recs = [
        _rec("account_service", "account_2", "USER_PROFILE", "ABSENT"),
        _rec("security_service", "audit_record_2", "SECURITY_AUDIT_LOG", "PRESENT",
             {"subject_reference": "user_2"}),
        _rec("integration_service", "data_flow_2", "DATA_FLOW", "ACTIVE"),
        _rec("backup_service", "backup_2", "BACKUP_ARCHIVE", "ACTIVE"),
    ]
    status2, steps2 = _run_synthetic(recs, "Erase my account please.", rules)
    expected2 = [
        ("FINDING", "integration_service", "data_flow_2", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
        ("FINDING", "backup_service", "backup_2", "REPORT_RESTORE_RISK", "ACTIVE"),
        ("REMEDIATION", "integration_service", "data_flow_2", "DISABLE_DATA_FLOW", "DISABLED"),
        ("REMEDIATION", "backup_service", "backup_2", "BLOCK_RESTORE", "BLOCKED"),
        ("VERIFICATION", "account_service", "account_2", "VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFICATION", "security_service", "audit_record_2", "VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFICATION", "integration_service", "data_flow_2", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ("VERIFICATION", "backup_service", "backup_2", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    ]
    cases.append(("active_sync_and_restorable_backup", "INCOMPLETE", status2, steps2, expected2))

    # Case 3: a data-access (non-deletion) request -> NOT_APPLICABLE.
    status3, steps3 = _run_synthetic(
        [], "I'd like to download a copy of my data. Please keep my account.", rules)
    cases.append(("non_deletion_access_request", "NOT_APPLICABLE", status3, steps3, []))
    return cases


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def render_report(agg: Aggregate, scores: list[CaseScore], cases) -> str:
    rp, rr, rf = agg.resource_prf()
    sp, sr, sf = agg.step_prf()
    L = []
    L.append("# GhostAudit — Evaluation Report\n")
    L.append("Generated by `code/evaluation/evaluate.py` over the public sample set "
             "(`sample_deletion_requests.csv` vs `sample_output.csv`, "
             f"{len(scores)} cases).\n")

    L.append("## Headline metrics\n")
    L.append("| Metric | Value |")
    L.append("| --- | --- |")
    L.append(f"| Case-level status accuracy | {agg.status_accuracy()*100:.1f}% "
             f"({sum(s.status_correct for s in scores)}/{len(scores)}) |")
    L.append(f"| Resource set — precision / recall / F1 | {rp*100:.1f}% / {rr*100:.1f}% / {rf*100:.1f}% |")
    L.append(f"| Step set — precision / recall / F1 | {sp*100:.1f}% / {sr*100:.1f}% / {sf*100:.1f}% |")
    L.append(f"| Field-level accuracy (position-aligned) | {agg.field_accuracy()*100:.1f}% |")
    L.append(f"| Sequence accuracy (exact order) | {agg.sequence_accuracy()*100:.1f}% "
             f"({sum(s.sequence_exact for s in scores)}/{len(scores)}) |")
    L.append(f"| Mean order similarity (LCS) | {agg.mean_lcs()*100:.1f}% |\n")

    L.append("## Per-case status\n")
    L.append("| case | expected | predicted | status | seq | step P/R |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for s in scores:
        sp_ = s.step_tp / (s.step_tp + s.step_fp) if (s.step_tp + s.step_fp) else 1.0
        sr_ = s.step_tp / (s.step_tp + s.step_fn) if (s.step_tp + s.step_fn) else 1.0
        L.append(f"| {s.case_id} | {s.expected_status} | {s.predicted_status} | "
                 f"{'OK' if s.status_correct else 'X'} | "
                 f"{'OK' if s.sequence_exact else 'X'} | {sp_*100:.0f}%/{sr_*100:.0f}% |")
    L.append("")

    mismatches = [s for s in scores if s.diff]
    L.append(f"## Mismatch diffs ({len(mismatches)})\n")
    for s in mismatches:
        L.append(f"### {s.case_id}  (expected {s.expected_status}, got {s.predicted_status})")
        L.append("```")
        L.append(s.diff)
        L.append("```")
    L.append("")

    L.append("## Additional evaluation cases (authored by this project)\n")
    L.append("Three hand-built edge cases run through the decision + assembly layers:\n")
    for name, exp_status, got_status, steps, expected in cases:
        got_sigs = [_sig(s) for s in steps]
        ok = (got_status == exp_status) and (got_sigs == expected)
        L.append(f"### {name} — {'PASS' if ok else 'FAIL'}")
        L.append(f"- expected status: `{exp_status}`, predicted: `{got_status}`")
        L.append(f"- expected {len(expected)} steps, predicted {len(steps)} steps"
                 f"{'' if got_sigs == expected else '  **(order/content differs)**'}")
        if not ok:
            L.append("```")
            L.append("  expected: " + str(expected))
            L.append("  predicted: " + str(got_sigs))
            L.append("```")
    L.append("")

    L.append("## Failures found and improvements made\n")
    L.append(_FAILURES_SECTION)
    return "\n".join(L)


_FAILURES_SECTION = """\
During development the evaluation surfaced several concrete defects, each fixed:

1. **Log level leaked into `system_id`.** The pipe-delimited `operations_stream`
   log parser split on `|` without dropping the empty leading field, so the
   level (`DEBUG`/`INFO`/`WARN`) was stored as the system. Observed as bogus
   `('DEBUG', 'SECURITY_AUDIT_LOG')` pairs; fixed by filtering empty fields.

2. **Embedded ledger rows mis-parsed.** Snapshot bundles contain an
   `operational_record_history` snapshot whose rows are themselves ledger
   records (`system`/`record_type`/`result`/`lookup_value`). These were read as
   flat records (wrong system, and `lookup_value` was not indexed), hiding real
   matches; fixed by detecting and parsing embedded ledger rows.

3. **Phone false positives in media extraction.** The vision fallback accepted
   any 7+ digit run as a phone, mis-reading dates/ids (e.g. `20264118`). Phone
   verification now requires an international `+<8-15 digits>` form.

4. **Claims overriding evidence.** State is now reconciled to the latest
   authoritative observation at `audit_at`, so a log/workflow "deletion complete"
   claim never overrides a later readback showing the record present
   (adversarial test `test_deletion_claim_overridden_by_later_evidence`).

5. **Backups double-counted.** `BACKUP_ARCHIVE` was handled by both retention
   (verify present) and recreation (verify restore-blocked); recreation now owns
   backups exclusively, matching the sample answers.

### Known open gap

Some subjects appear in **no text evidence** at `audit_at` (absent-account
readback probes store a `resource_id` with a null profile, so there is no
identifier to match on; a few subjects are only present in image evidence). Those
cases currently reconcile to an empty COMPLETE. The planned fix is a resource-id
linking pass in discovery (identifier -> `resource_id` via the activity catalog,
then match absent-record observations by `resource_id`) plus the vision run on
image evidence, so COMPLETE cases can cite the 404 / NOT_FOUND evidence.
"""


def main() -> int:
    dataset_dir = _REPO_ROOT / "dataset"
    agg, scores = evaluate(
        dataset_dir,
        dataset_dir / "sample_deletion_requests.csv",
        dataset_dir / "sample_output.csv",
    )
    rules = RuleBook.from_dataset(load_dataset(dataset_dir))
    cases = custom_cases(rules)
    report = render_report(agg, scores, cases)
    out = _CODE_DIR / "evaluation" / "evaluation_report.md"
    out.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n[written to {out}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
