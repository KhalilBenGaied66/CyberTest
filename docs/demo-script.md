# Three-minute demo script

Preparation: lab running, `.env` loaded, an empty `SOAR_DATA_DIR`, the Shuffle execution list open, and a terminal in the repo. The offline segment can be shown with `phishing-soar --offline` if the Shuffle lab is not up.

| Time | Screen / action | Narration |
|---:|---|---|
| 0:00–0:20 | README architecture and safety banner | Two sources, one shared pipeline, a human gate, lab-only reversible response; synthetic data; no URL visits or uploads. |
| 0:20–0:45 | `scripts/submit_wazuh_fixture.py … w1_bruteforce_success.json`; open the Shuffle execution | The normalized fields (rule, agent, srcip, user, counts) and the dedupe key `manager:alert_id`. |
| 0:45–1:15 | Card / `show-case` factor table | Recompute 90: 35+5 reputation, 15+10+15 behaviour, 10 root. Local mirror plus ThreatFox; VT disabled. |
| 1:15–1:45 | Approval step | Exact action, scope `agent:linux-lab-01`, 3600 s TTL, rollback method. Enter the reason and approve. |
| 1:45–2:05 | Response and audit | Simulated block receipt (`verified: true`), the `action` audit event linked to the decision hash; `phishing-soar expire` after the accelerated TTL shows the rollback receipt. |
| 2:05–2:25 | Submit P3, reject | Score 5: a Return-Path mismatch on a legitimate ESP. Human false-positive decision, no containment, closure record. |
| 2:25–2:45 | `phishing-soar --offline ingest-email p1_credential_harvest.eml` | Local exact hit, `local_only`, score 69, still reaches approval. Unknown is not clean. |
| 2:45–3:00 | `pytest` count, `verify-audit`, metrics table, repo tree | Test coverage, an intact audit chain, the honestly measured metrics. Summarise the skills shown. |

For a fully deterministic run without lab services: `python scripts/run_demo.py --show-card`.
