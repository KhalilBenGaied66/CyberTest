# Metrics method

The goal is an honest statement such as "In N synthetic runs, median analyst hands-on triage fell from X to Y minutes; end-to-end time varied with human approval and is reported separately". It is published only once the runs exist.

## Clocks

| Metric | Start | Stop | Source |
|---|---|---|---|
| Machine processing time | intake accepted | approval card ready | `timings.received_at` → `timings.card_ready_at` |
| Analyst hands-on time | analyst opens evidence | decision submitted | `analyst_active_seconds` in the decision (stopwatch, self-reported) |
| Approval wait | card ready | decision submitted | `card_ready_at` → `decided_at` |
| Response execution | decision submitted | action verified | `decided_at` → `response_verified_at` |
| Time to triage | intake accepted | verdict submitted | `received_at` → `decided_at` |
| Time to contain | intake accepted | approved action verified | `received_at` → `response_verified_at` (malicious cases only) |

Do not call any of these MTTR. Recovery is not measured here.

## Manual baseline

1. Before using the playbook, investigate P1, P2, P3 and W1 by hand with the same allowed sources and a written checklist: parse headers or the alert, extract IOCs, look up local and provider data, compute the score, write notes, propose an action.
2. Time only active work. Exclude lab setup and learning time.
3. Do one practice round, then at least three measured rounds.

## Automated runs

1. Run each scenario at least five times, labelled with `--scenario` (CLI) or `labels.scenario` (API).
2. Keep cold-cache runs (fresh `SOAR_DATA_DIR` or expired cache) separate from warm-cache runs. `cache_mode` is derived per case.
3. Record provider availability, and whether the response was simulated.
4. Enter `analyst_active_seconds` with each decision (`--active-seconds`).
5. Export the rows: `phishing-soar metrics --out data/runtime/metrics.csv`.

## Reporting

```text
hands_on_reduction_pct       = (manual_median - automated_hands_on_median) / manual_median * 100
elapsed_triage_reduction_pct = (manual_time_to_triage_median - automated_time_to_triage_median)
                               / manual_time_to_triage_median * 100
```

Report median and range, the sample size, cache mode, provider availability, simulated vs real response, and approval delay. Never report a single best run, and never report planned estimates as results.

## Results

Not yet measured.
