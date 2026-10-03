# Investigation report: `<case_id>`

```text
Case ID / source / timestamps:
  case_id:            <uuid>
  source:             email | wazuh   (source_event_id: …)
  received / observed / decided / contained (UTC):

Executive verdict: malicious | benign | suspicious_no_action

Scope and affected asset/user:

Email authentication or Wazuh event summary:
  (trusted authserv-id, SPF/DKIM/DMARC, boundary hop) | (rule id/level, agent, srcip, user, counts)

Indicators and provenance (defanged):
  type | value | first seen in | scope | scoring eligible

Enrichment results and provider health:
  provider | status | match | verdict | reason      completeness: …  mode: …  local feed age: …

Risk score, band, model version, and factor table:
  factor | evidence | applied/nominal | cap | source        total = …

Analyst reasoning and uncertainty:

Approved actions, TTL, verification, rollback ID:
  action_id | type | target | scope | TTL | verified | rollback_id | removed_at

Notifications/ticket references:

Timeline:
  (copy from the ticket's Timeline section / audit events)

Lessons/tuning recommendations:

Evidence hashes:
  raw artifact sha256: …
  audit event hashes for decision and action: …
```

Most fields can be filled from `phishing-soar show-case <case_id>` and `data/runtime/tickets/<case_id>.md`.
