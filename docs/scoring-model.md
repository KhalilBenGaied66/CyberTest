# Scoring model (`email-1.0`, `wazuh-1.0`)

```text
score = min(100, Σ over categories of min(Σ factor points, category cap))

0–29   LOW     routine analyst review; no containment proposed
30–59  MEDIUM  prompt review; containment proposed only for an exact-match safe target
60–100 HIGH    urgent review; containment proposed if a safe target exists
```

- The score prioritises; the analyst verdict (`malicious`, `benign`, `suspicious_no_action`) is separate.
- Unknown or unavailable data adds **zero** and is listed under `unknowns`. It never lowers risk and never means clean.
- Repeated evidence scores once (the strongest factor), unless the table says the factors add.
- Reputation uses the single best indicator: the highest exact-match tier, plus at most one corroboration bonus.
- Every factor records `factor_id`, `category`, `evidence`, `points`, `applied_points`, `cap`, `source`, `indicator_id`. `recompute_total()` reproduces the total from those fields alone.
- Weights live in `src/phishing_soar/scoring_model.json`. Change one factor or cap at a time, bump the version, and rerun the full fixture suite. Historical cases keep their `model_version`.

## Email profile (`email-1.0`)

| Category (cap) | Factor | Points | Implementation notes |
|---|---|---:|---|
| Reputation (35) | `rep_exact`: exact malicious URL/domain/hash/IP in URLhaus, ThreatFox or an unexpired local IOC | 30 | URLhaus *host* hits are `suspicious` context only (shared hosting); stale local IOCs never count; IPs from Received hops count only from the trusted boundary hop |
| | `rep_vt_high`: VT ≥ 5 malicious engines | 25 | Only without an exact hit |
| | `rep_vt_low`: VT 1–4 malicious engines | 10 | Only without a stronger factor |
| | `rep_corrob`: an independent second source on the same exact IOC | +5 | VT counts as a source at ≥ 5 engines |
| Authentication (20) | `auth_dmarc_fail` | 10 | Trusted `Authentication-Results` only |
| | `auth_spf_fail` / `auth_spf_softfail` | 5 / 3 | |
| | `auth_dkim_fail` | 5 | Only when no DKIM signature passes |
| Identity (15) | `id_return_path_mismatch`: From vs Return-Path organizational domain | 5 | Common on legitimate ESPs (P3) |
| | `id_reply_to_mismatch` | 5 | |
| | `id_display_name_impersonation` | 5 | Display name contains a `protected_display_names` entry and the sender is not internal/allowlisted |
| Content (30) | `content_dangerous_attachment`: executable, script, macro-enabled Office, password-protected archive | 12 | Also PE magic hidden behind another extension |
| | `content_attachment_type_mismatch`: MIME/extension or magic/extension mismatch, double extension | 6 | `application/octet-stream` for a known extension counts (tuning candidate) |
| | `content_deceptive_link`: link-text mismatch, Punycode, IP-literal host, embedded credentials | 8 | Once |
| | `content_credential_lure`: credential/urgent language plus ≥ 1 web link | 6 | Phrase list in `email_parser.CREDENTIAL_PHRASES` |
| | `content_shortener_or_port`: URL shortener or non-standard port | 4 | |

Recorded but worth 0 points in v1: disk-image and HTML/SVG attachments, `pass_unaligned` DKIM, missing Message-ID or Date, data:/javascript: URLs. All of these appear in the case evidence.

## Wazuh profile (`wazuh-1.0`)

| Category (cap) | Factor | Points |
|---|---|---:|
| Reputation (40) | `rep_exact`: exact malicious source IP in ThreatFox or an unexpired local IOC | 35 |
| | `rep_vt_high`: VT ≥ 5 (no exact hit) | 25 |
| | `rep_corrob` | +5 |
| Behavior (40) | `auth_fail_burst`: ≥ 10 failures from one IP in 5 min | 15 |
| | `multi_user`: ≥ 3 distinct usernames in 5 min | 10 |
| | `success_after_fail`: success after failures from the same IP | 15 |
| | `high_severity_no_counts`: level ≥ 10 and all behaviour counts unavailable | 10 |
| Context (20) | `privileged_user`: `privileged_users` or `service_account_prefixes` | 10 |
| | `critical_asset`: agent in `critical_internet_facing_assets` | 5 |
| | `watchlist_source`: source IP in `watchlist_networks` (not the IOC list) | 5 |

Behaviour counts come from the integration when it supplies them. Otherwise `authentication_failures_5m` and `distinct_users_5m` are derived from `previous_output` (frequency rules such as 5712), and `success_after_failures` is set by rule 100110.

## Worked examples (reproduced by the test suite)

| Case | Factors | Total |
|---|---|---|
| P1 credential harvest | rep 30+5, DMARC 10, SPF fail 5, Return-Path 5, Reply-To 5, deceptive link 8, credential lure 6 | **74 HIGH** |
| P1, all providers down | same minus corroboration; `local_only` | **69 HIGH** |
| P2 macro attachment, auth all pass | rep 30+5, dangerous attachment 12, type mismatch 6 | **53 MEDIUM** (no blockable target ⇒ no containment proposed) |
| P3 benign SaaS | Return-Path mismatch 5 | **5 LOW** |
| W1 brute force then success | rep 35+5, failures 15, users 10, success 15, root 10 | **90 HIGH** |

The display-name factor is policy-driven. The lab policy protects the organisation's own names ("Lab Corp", "Lab IT Helpdesk"), so P1's "Microsoft Support" does not fire it and P1 stays at the blueprint's 74. Adding `"microsoft"` to `protected_display_names` raises P1 to 79; `test_display_name_impersonation_is_policy_driven` covers this.

## Completeness (reported separately, never folded into the score)

```text
completeness_ratio = answered applicable checks / applicable checks     (local checks included)
complete ≥ 0.80; partial 0.40–0.79; local_only < 0.40 or no remote check answered
enrichment_mode: online (all remote answered) | degraded (some unknown) | offline (none answered)
```

"74 HIGH, local_only" stays high because the local exact match and the message evidence support it. "12 LOW, local_only" means low *observed* risk with limited intelligence, not "safe".

## Containment proposal rules

- Email: the exact-malicious IP or domain itself, or the host of an exact-malicious URL, up to three targets. Hashes and email addresses are never block targets.
- Wazuh: the source IP when the band is HIGH, or MEDIUM with an exact reputation hit. Scope is `agent:<name>`.
- Every candidate goes through `response.safety.check_block_target` before it is proposed and again before it is applied. Private, loopback, reserved, protected, allowlisted, internal and shared-shortener targets are refused. A refused allowlisted target sets `allowlist_conflict`, and the evidence still counts.

## Tuning workflow

1. Close each case with a verdict and reason. Read the false positives at the factor level.
2. Change one factor or cap in `scoring_model.json`, bump the model version, and record why.
3. Run `pytest` (golden and boundary tests) and `scripts/run_demo.py --check`.
4. Never rewrite historical scores. Old cases keep their `model_version`.
