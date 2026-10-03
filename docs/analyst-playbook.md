# Analyst playbook

## 1. Purpose, severity and SLA

You decide whether a reported email or a Wazuh authentication alert is malicious, and whether the proposed **bounded, reversible** lab action may run. The playbook prepares evidence; it never contains on its own.

| Band | Score | Target SLA (production) | Lab approval window |
|---|---|---|---|
| HIGH | 60–100 | 15 min | 30 min |
| MEDIUM | 30–59 | 30 min | 30 min |
| LOW | 0–29 | 4 h | 30 min (demo) |

## 2. Validating email authentication and the Received chain

- Trust only the `Authentication-Results` header written by our receiving MTA (`authserv-id` in `trusted_authserv_ids`). The card shows which one was used and lists ignored copies; an attacker can insert their own `dmarc=pass` lower in the headers (P1 does exactly this).
- `Received` hops are read top-down. Hops added by `trusted_mta_hosts` are trusted. The first one that received from outside is the **boundary**, and its connecting IP is the closest trustworthy origin. Everything below it can be forged and is never scored.
- SPF authenticates the envelope domain, not the visible From. Aligned DKIM and DMARC pass mean the sending domain authorised the message. **None of them means the content is benign** (see P2).

## 3. Reading enrichment

| Result | Meaning |
|---|---|
| `status=ok, match=true, verdict=malicious` | The provider answered and has an exact malicious record |
| `status=ok, match=false` (`no_result`, `no_detections`) | The provider answered and has no record. Absence of evidence, not proof of safety |
| `status=ok, verdict=suspicious` | Context only, e.g. a URLhaus host hit on possibly shared infrastructure |
| `status=ok, verdict=stale` | A local IOC that has expired. Shown, never scored |
| `status=unknown` (`timeout`, `rate_limited`, `circuit_open`, `not_configured`, `offline`, `budget_exhausted`) | The provider could not answer. **Never treat it as clean** |
| `status=skipped` | Policy prevented an external lookup (private IP, internal domain) |

`completeness` and `enrichment_mode` on the card tell you how much intelligence actually answered.

## 4. Recomputing and overriding the score

Each factor shows its applied/nominal points and category cap. Sum the applied points to check the total. The score is a priority, not a verdict: you may judge a MEDIUM case malicious (P2) or a HIGH case benign (an authorised red-team source). In both cases the reason field must explain why.

## 5. Decision criteria

**Approve (verdict `malicious`)** when the evidence shows malicious intent *and* the proposed target is the exact observed host or IP. Examples of reasons:

- "Punycode look-alike of portal.example.com, exact URL match local + URLhaus, DMARC fail."
- "18 failures across 3 users then root login from 198.51.100.44; exact IOC corroborated by ThreatFox."

**Reject (verdict `benign` or `suspicious_no_action`)** when the evidence is explained by legitimate behaviour, or the target is not safe to block. Examples:

- "Vendor ESP bounce domain; DKIM aligned to saas-vendor.example; link to the known app domain."
- "Source IP is the scheduled vulnerability scanner."

Every decision needs a reason of at least 10 characters. Approve only the action IDs you have checked; you may approve the verdict and select no actions.

## 6. Protected targets and allowlists

Containment is refused, even after approval, for private, loopback, link-local, reserved and management networks (`protected_networks`), allowlisted IPs and domains, internal domains, protected domains and shared URL shorteners. An allowlist hit never erases evidence. The block is not proposed, the card shows `allowlist_conflict` (or `containment_suppressed:<reason>`), and an approval of such a case ends in `needs_review` rather than `responded`, so someone resolves the conflict deliberately.

## 7. Verifying and rolling back a temporary block

- Each receipt carries `action_id`, `rollback_id`, `target`, `scope`, `expires_at` and `verified`.
- Blocks expire automatically: `POST /v1/jobs/expire` runs every minute and writes a `rollback` audit event.
- Manual rollback: `phishing-soar rollback <rollback_id> --analyst <you> --reason "<why>"`, or `POST /v1/actions/<rollback_id>/rollback`. Repeating it is safe and returns `already_removed`.

## 8. Degraded and failure procedures

| Situation | What you see | What to do |
|---|---|---|
| APIs down / rate-limited | `enrichment_mode=offline` or `degraded`, unknowns listed | Decide on the available evidence; note the reduced intelligence in the reason |
| Malformed `.eml` | `parse_partial` flag, parse warnings | Inspect the raw artifact in an isolated viewer; never open links or attachments |
| Duplicate submission | Intake returns the original `case_id` and `duplicate_suppressed` | Nothing; the original case carries the decision |
| Approval timeout | `approval_timeout` → `needs_review`, escalation notification | Review manually; re-submit only if new evidence appears (a new case) |
| Response failure | `response_failed_needs_review`, high-priority notification | Check the current block state; contain manually if justified; document it |
| Rollback failure | `rollback_failure` notification; the block stays active and is retried every minute | Remove it manually; confirm with `show-case` |

## 9. Escalation and evidence handling

- Raw evidence lives in `data/runtime/cases/<id>/raw/` with mode 0600. Never attach it to tickets or chat.
- Never paste live URLs. Use the defanged forms (`hxxps://…[.]…`).
- Escalate to incident response when a privileged login succeeded (W1), credentials were entered, or several users clicked.

## 10. Closure codes and tuning feedback

| Outcome | Meaning |
|---|---|
| `responded` | Approved; actions applied and verified; notifications sent |
| `response_partial` | Actions applied, but a notification failed |
| `response_failed_needs_review` | An approved action could not be applied |
| `needs_review` | Timed out, or containment refused for a protected/allowlisted target |
| `closed` | Rejected; no containment |
| `failed_needs_review` | Internal error; the audit log has the stage and error |

Record recurring false-positive factors (for example `id_return_path_mismatch` on known ESPs) and propose one versioned weight change at a time ([scoring-model.md](scoring-model.md#tuning-workflow)).

## Appendix: sample sshd lines for `wazuh-logtest`

```text
Oct  3 01:18:01 linux-lab-01 sshd[2201]: Failed password for invalid user admin from 198.51.100.44 port 50001 ssh2
Oct  3 01:18:03 linux-lab-01 sshd[2202]: Failed password for invalid user oracle from 198.51.100.44 port 50002 ssh2
Oct  3 01:18:05 linux-lab-01 sshd[2203]: Failed password for root from 198.51.100.44 port 50003 ssh2
(repeat until rule 5712 fires)
Oct  3 01:18:22 linux-lab-01 sshd[2211]: Accepted password for root from 198.51.100.44 port 51122 ssh2
```
