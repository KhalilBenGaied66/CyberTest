# Architecture

## Components

| Component | Role | Where |
|---|---|---|
| Shuffle (self-hosted OSS) | Webhooks, orchestration, User Input pause, schedules, visual execution trace | `workflows/` (design + exports) |
| `phishing_soar` service | Deterministic parsing, normalization, enrichment, scoring, approval validation, response, audit | `src/phishing_soar/` |
| Wazuh (all-in-one) | Authentication / malicious-IP alerts; custom integration posts to Shuffle | `wazuh/` |
| SQLite | Dedupe keys, case status, provider cache, circuit breakers, VT budget, approvals, actions and expiries | `data/runtime/state/soar.db` |
| JSONL / JSON | Local IOC mirror, hash-chained audit ledger, per-case snapshot and events, block operation log | `data/ioc/`, `data/runtime/` |
| Markdown | Human-readable tickets | `data/runtime/tickets/` |
| Mailpit or file outbox | Analyst / reporter notifications | `SOAR_NOTIFY_MODE` |

Shuffle never holds business logic. It calls the service, branches on the JSON it gets back, pauses for the analyst, and calls the service again with the decision. That keeps every rule unit-testable, and a workflow export only has to show wiring.

## Module map

| Blueprint stage | Module | Key behaviour |
|---|---|---|
| Intake | `pipeline.ingest_email`, `pipeline.ingest_wazuh`, `service` | Size limits, empty-file rejection, bearer auth, generated raw filenames (0600), SHA-256 receipt |
| Normalize | `email_parser.normalize_email`, `wazuh_normalizer.normalize_wazuh` | One `NormalizedCase v1` for both sources (`schemas/normalized-case.schema.json`) |
| Deduplicate | `state.claim_dedupe` | Email raw SHA-256; Wazuh `manager:alert_id`; canonical-JSON fallback; 24 h window in one SQLite transaction |
| Extract | `email_parser`, `indicators.IndicatorCollector`, `canonical` | Typed indicators with provenance, scope, `scoring_eligible`, defanged display |
| Enrich | `enrichment.engine.Enricher` | Local IOC (always) → cache → URLhaus/ThreatFox → optional VT; retry, 429, circuit breaker, budget |
| Score | `scoring.score_case` + `scoring_model.json` | Versioned pure function; per-factor evidence; caps; unknowns; containment proposal with safety pre-check |
| Approve | `approval.ApprovalGate` | Hashed single-use token bound to case + action hash; validation before any state change; timeout |
| Respond | `response.SimulatedBlocklist`, `response.safety` | Re-validate target, TTL ≤ 3600 s, idempotent add/remove, verify, rollback ID |
| Audit | `audit.AuditLedger`, `audit.verify_chain` | Append-only JSONL, `prev_event_hash` / `event_hash`, fsync, file lock, redaction |
| Tickets / notify | `tickets`, `notify` | Analyst card, Markdown + JSON ticket, file/SMTP notifier |
| Metrics | `metrics` | Separate clocks from snapshot timings |

## Case lifecycle

```text
received → normalized | parse_partial → enriched | enriched_degraded → scored → awaiting_approval
        → approved → responded | response_partial | response_failed_needs_review | needs_review → audited
        → rejected → closed → audited
        → approval_timeout → needs_review → audited
any non-terminal state → failed_needs_review   (internal error, audited)
duplicates never create a case: they add a duplicate_suppressed event to the original
```

`models.CASE_TRANSITIONS` enforces the transitions inside the same SQLite transaction that records them, so a state can never move backwards.

## Data at rest

```text
data/runtime/
├── audit/events-YYYY-MM.jsonl          append-only, hash-chained ledger
├── cases/<case_id>/case.json           latest portable snapshot (no tokens, no message body)
├── cases/<case_id>/events.jsonl        this case's ledger events
├── cases/<case_id>/raw/<random>.eml    original evidence, mode 0600, never served
├── state/soar.db                       SQLite (WAL)
├── tickets/<case_id>.md|.json          human-readable ticket + status record
├── notifications/outbox.jsonl          file notifier output
├── blocklist/temporary_blocks.jsonl    simulated block add/remove operations
└── provider_responses/<sha256>.json    size-limited raw provider answers, referenced by raw_ref
```

## Lab deployment

The core runs on one Linux VM (practical target: 8 vCPU, 16 GB RAM, 120 GB SSD), or on two smaller VMs with Wazuh on one and Shuffle plus the SOAR API on the other.

1. **SOAR API + Mailpit:** `cp .env.example .env`, set `SOAR_API_TOKEN`, then `docker compose -f docker-compose.lab.yml up -d --build`. The API binds to `127.0.0.1:8088` by default; change the port mapping to the lab interface only if Shuffle runs elsewhere.
2. **Shuffle:** deploy Shuffle OSS from its upstream Docker Compose instructions and pin the version you test with. Make the SOAR API reachable from Shuffle's app containers, either by attaching the Shuffle network to `soar-api` or by using the lab IP. Build the workflows in [`workflows/EXPORT_NOTES.md`](../workflows/EXPORT_NOTES.md).
3. **Wazuh:** use the all-in-one quickstart, enroll `linux-lab-01`, add [`wazuh/custom-rules.xml`](../wazuh/custom-rules.xml) and [`wazuh/ossec-integration.example.xml`](../wazuh/ossec-integration.example.xml), and point `hook_url` at the Shuffle webhook.
4. **Schedules:** call `POST /v1/jobs/approval-timeouts` every 5 minutes and `POST /v1/jobs/expire` every minute (Shuffle schedule triggers or cron), and run `scripts/verify_audit_chain.py` nightly.

`docker-compose.lab.yml` has not been exercised yet: the build environment for this commit had no Docker daemon. Validate it on the lab VM first.
