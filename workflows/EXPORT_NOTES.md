# Shuffle workflow design and export notes

**Status: designed, not yet built.** The JSON exports (`wf-email-intake.json`, `wf-wazuh-intake.json`, `sf-notify-approve.json`, `sf-respond-audit.json`) will be added here after the workflows have been built and tested in a pinned Shuffle OSS version and re-imported into a clean lab once. No hand-written "exports" are committed: they would not prove anything.

All decision logic lives in the SOAR API (`phishing-soar serve`). Shuffle supplies the webhooks, the branching, the analyst pause, the schedules and the execution trace. Every HTTP node sends `Authorization: Bearer <SOAR_API_TOKEN>` from Shuffle's stored authentication, never from a literal in the workflow.

## WF-EMAIL-INTAKE

| # | Node (app / action) | Input | Output / branch |
|---|---|---|---|
| 1 | Webhook trigger `email-intake` (require an auth header) | `scripts/submit_eml.py` JSON: `eml_base64`, `reporter`, `reported_at`, optional `labels` | `$exec` |
| 2 | HTTP POST `{{soar_api}}/v1/intake/email`, header `X-Shuffle-Execution-Id: $exec.execution_id` | `$exec` body unchanged | Case summary: `case_id`, `duplicate`, `score`, `enrichment`, `proposed_actions`, `card`, `approval.token`, `approval.expires_at` |
| 3 | Condition: `$intake.body.duplicate` is `true` | | → end (the API already wrote `duplicate_suppressed` on the original case) |
| 4 | Subflow `SF-NOTIFY-AND-APPROVE` | `case_id`, `card`, `proposed_actions`, `approval` | Analyst decision |
| 5 | Subflow `SF-RESPOND-AUDIT` | decision + `approval.token` | `outcome`, `actions` |

The blueprint's `SF-ENRICH-SCORE` is collapsed into node 2. Enrichment and scoring run server-side in the same request as intake, so no case can be scored without its `received`, `normalized`, `enriched` and `scored` audit events. The Shuffle trace shows the result of that single node.

## WF-WAZUH-INTAKE

| # | Node | Input | Output / branch |
|---|---|---|---|
| 1 | Webhook trigger `wazuh-intake` (require the same bearer header the integration sends) | Envelope from `wazuh/shuffle-integration.example.py` | `$exec` |
| 2 | HTTP POST `{{soar_api}}/v1/intake/wazuh` | `$exec` | Case summary (400 `rule_not_allowlisted` / `missing_rule_id` ends the run; the rejection is already audited) |
| 3–5 | Same as email nodes 3–5 | | |

## SF-NOTIFY-AND-APPROVE

1. **User Input** trigger. The message is the analyst card (`card`), which is already defanged and token-free. It offers *continue* (approve) and *abort* (reject).
2. Decision fields: `decision`, `verdict`, `reason` (≥ 10 characters), `analyst`, `approved_actions[]`, and optionally `analyst_active_seconds`.
   **To validate on the pinned version:** whether Shuffle OSS User Input can collect free-text fields. If it cannot, the analyst submits the decision with `phishing-soar decide` (or a small form posting to `/v1/cases/<id>/decision`). The subflow then only waits, and the approval-timeout schedule remains the authority.
3. The User Input timeout should be ≥ the SOAR approval timeout (30 min). The SOAR expiry is authoritative: a late *continue* returns `approval_expired` and never contains.

## SF-RESPOND-AUDIT

| # | Node | Input | Output / branch |
|---|---|---|---|
| 1 | HTTP POST `{{soar_api}}/v1/cases/{{case_id}}/decision` | `{"token": approval.token, "decision", "verdict", "reason", "analyst", "approved_actions"}` | `result`, `outcome`, `actions[]` |
| 2 | Condition on `outcome` | | `responded` → end; `needs_review` / `response_failed_needs_review` / `response_partial` → notify the on-call channel (the API has already written the audit and outbox notifications) |

Continue never maps straight to the firewall. The API re-checks the token, the case state, the reason, the action hash and target safety before calling the response adapter.

## Schedules

| Workflow | Trigger | Call |
|---|---|---|
| WF-SCHEDULE-TIMEOUTS | every 5 min | `POST /v1/jobs/approval-timeouts` |
| WF-SCHEDULE-EXPIRY | every 1 min | `POST /v1/jobs/expire` |
| (cron on the SOAR host) | nightly | `scripts/verify_audit_chain.py data/runtime/audit` |
| (cron on the SOAR host) | every 6 h | `scripts/refresh_ioc_mirror.py --out data/ioc/threatfox_mirror.jsonl` |

## Known limitation

The single-use approval token passes through Shuffle execution data, so anyone who can read Shuffle executions could use it within its 30-minute life. In the lab, Shuffle access equals analyst access. Production would bind decisions to SSO identity instead.

## Export checklist

- [ ] Shuffle version and the app versions used (HTTP, Shuffle Tools) recorded here
- [ ] Workflow IDs, org IDs, webhook URLs, auth values and execution data removed from the JSON
- [ ] Screenshot of each workflow in `docs/screenshots/`
- [ ] A node → input/output table above, kept in sync with the export
- [ ] Re-imported into a clean Shuffle instance and the four fixtures replayed successfully
