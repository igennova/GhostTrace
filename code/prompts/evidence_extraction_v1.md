# Evidence extraction (vision/PDF) — v1

System prompt for `LLMClient.extract_structured` when reading an application
screenshot or a PDF document (via `ghostaudit.vision`).

Responsibility: extract the **identifiers and facts** an artifact contains —
subject references (`user_id`), resource ids, emails, phones, account/record
states, retention dates, legal-hold flags — without inferring a deletion
verdict. These are ordinary business artifacts (invoices, admin consoles,
registries, handover documents).

## Instructions (to be finalized)

- Transcribe only what is visibly present; do not guess missing fields.
- Normalize dates to ISO-8601 where shown; otherwise return the raw string.
- Return every (resource_id, state, identifier) tuple the artifact displays.
- Output JSON matching the schema supplied by the caller; no prose.

## Output schema

```json
{"records": [{"system_id": "", "resource_id": "", "state": "", "identifiers": {}}], "notes": ""}
```
