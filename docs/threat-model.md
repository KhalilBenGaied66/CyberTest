# Threat model

Scope: the lab SOAR (Shuffle, `phishing_soar` API, SQLite/JSONL state, Wazuh integration) processing **hostile input by design**: phishing emails and attacker-influenced log fields.

## Assets

| Asset | Why it matters |
|---|---|
| Containment capability (blocklist) | Misuse could cut off legitimate services or the management path |
| Approval tokens and API token | Possession allows decisions or intake |
| Raw evidence (`.eml`, alerts) | May contain personal data or live malicious content |
| Audit ledger | Basis for accountability and incident review |
| Provider API keys | Quota and account abuse |
| Scoring integrity | A manipulated score could rush an analyst or bury an incident |

## Trust boundaries

1. Reporter / Wazuh → Shuffle webhook → SOAR API (untrusted content, authenticated transport)
2. SOAR API → external reputation providers (outbound only, lookups only)
3. Analyst → decision endpoint (authenticated, token-bound)
4. SOAR → response adapter (simulated list; later a single lab agent)

## Threats and controls (STRIDE)

| Threat | Example | Control in this build | Residual risk / production need |
|---|---|---|---|
| **Spoofing** an intake source | Forged alert posted to the webhook | Bearer token on every API route (constant-time compare); Wazuh rule allowlist re-checked server-side; bind to the lab network | Use mTLS or a per-source token, and rotate tokens |
| Spoofing an analyst | Forged approval callback | Random single-use token, stored hashed, bound to case and action hash, 30-minute expiry; forged attempts are audited | Local identity only; production needs SSO/RBAC and a second approver for high impact |
| Spoofed authentication results | Attacker adds `dmarc=pass` header | Only the topmost header from a trusted `authserv-id` is used; others are listed as ignored | Needs the correct MTA boundary from the mail team |
| Forged `Received` hops | Fake origin IP | Trust labels from the trusted boundary; IPs below it are never scored | Same as above |
| **Tampering** with evidence or ledger | Edit audit lines to hide an approval | SHA-256 hash chain, per-case sequence, fsync, `verify_chain`, raw evidence hashed at receipt | Local files are tamper-evident only; forward to WORM/central storage |
| Tampering with a proposal between card and approval | Swap the block target | Approval bound to `proposed_action_hash`; adapter re-validates the target and TTL at execution | — |
| **Repudiation** | "I never approved that" | Analyst identity, reason, timestamp and action hash in the decision event, linked to the action event | Stronger identity (SSO) |
| **Information disclosure** | Tokens or bodies in logs/tickets | Tokens never persisted; recursive redaction of secret keys and values in audit; snapshots exclude bodies; raw files 0600 under generated names; defanged display | Encrypt at rest; retention policy |
| Leaking internal indicators to third parties | Private IPs or internal domains sent to providers | Scope check: private/reserved IPs and internal domains are never looked up externally; no uploads ever | Review provider terms |
| **Denial of service** | Huge MIME bomb, deep nesting, giant provider reply | 10 MB `.eml` / 256 KB alert limits, Content-Length required, MIME part and depth limits, no archive extraction, 1 MB provider response cap, 5 s / 10 s timeouts | Rate-limit intake per source |
| Provider outage or quota exhaustion | 429 storm | Circuit breaker, Retry-After, VT budget, local IOC mirror, `unknown` ≠ clean | — |
| **Elevation / destructive action** | Score alone triggers containment | Containment only after explicit approval; simulate by default; TTL ≤ 60 min; exact target only; protected/allowlisted/private refusal; idempotent add/remove | Real adapters must use scoped credentials on a dedicated list |
| Malicious content execution | Analyst or system opens a link or attachment | Parser never renders, fetches, resolves or executes anything; nested messages and archives are hashed, not opened | Analyst workstation hygiene |
| Parser exploitation | Crafted headers or HTML | Stdlib `email` with `policy.default`, `HTMLParser` (no rendering), exceptions → `parse_partial` | Keep Python patched |
| Replay / duplicate | Same alert resent to trigger a second block | Dedupe key in one transaction; duplicates link to the original and cannot act | — |

## Assumptions

- The lab network is isolated from production, and the SOAR API is not exposed to the internet.
- Fixtures use reserved names (`.test`, `.example`) and documentation IP ranges. `SOAR_LAB_DOC_RANGES_ROUTABLE` exists only so those fixtures can exercise enrichment and blocking.
- Secrets live in `.env` (Git-ignored), not in workflow exports.
