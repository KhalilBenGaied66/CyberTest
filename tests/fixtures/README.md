# Test fixtures

Everything here is synthetic and inert. Domains use the reserved `.test` / `.example` TLDs and IPs use RFC 5737 documentation ranges. The "macro" attachment in P2 is a tiny ZIP holding a text file; it contains no macros.

| Fixture | Scenario | Expected |
|---|---|---|
| `eml/p1_credential_harvest.eml` | Punycode look-alike credential page, DMARC/SPF fail, Return-Path and Reply-To mismatch, forged lower `Authentication-Results` and `Received` hop | 74 HIGH (69 HIGH offline) |
| `eml/p1_truncated.eml` | P1 cut mid-HTML (missing closing boundary) | `parse_partial`, no crash |
| `eml/p2_malicious_attachment.eml` | `invoice.docm` sent as `application/octet-stream`, all authentication passes | 53 MEDIUM, no containment target |
| `eml/p3_benign_saas.eml` | Legitimate ESP with a separate bounce domain | 5 LOW |
| `wazuh/w1_bruteforce_success.json` | 18 failures / 3 users then root success from 198.51.100.44 | 90 HIGH |
| `wazuh/w2_bare_alert_previous_output.json` | Bare rule-5712 alert; counts derived from `previous_output` | 35 MEDIUM |
| `wazuh/invalid_*.json` | Missing rule ID; rule outside the allowlist | Rejected and audited |
| `local_iocs.jsonl` | Seeds for P1 URL, P2 hash, W1 IP, plus one expired entry | |
| `provider_responses/` | Recorded URLhaus/ThreatFox answers plus `manifest.json` for `ReplayTransport` | |
