"""Metrics from case snapshots and audit timestamps.

Clocks are kept separate on purpose: machine processing time, analyst
hands-on time (self-reported in the decision form), approval wait, response
execution, time to triage and time to contain. Nothing here is called MTTR.
"""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path
from typing import Any

from .util import parse_timestamp

COLUMNS = (
    "case_id",
    "source_type",
    "scenario",
    "score",
    "band",
    "enrichment_mode",
    "cache_mode",
    "processing_seconds",
    "analyst_active_seconds",
    "approval_wait_seconds",
    "response_seconds",
    "time_to_triage_seconds",
    "time_to_contain_seconds",
    "outcome",
    "duplicate",
    "error_count",
)


def _seconds(start: str | None, end: str | None) -> float | None:
    a, b = parse_timestamp(start), parse_timestamp(end)
    if a is None or b is None:
        return None
    return round((b - a).total_seconds(), 3)


def case_row(snapshot: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    timings = snapshot.get("timings", {})
    score = snapshot.get("score") or {}
    enrichment = snapshot.get("enrichment") or {}
    decision = snapshot.get("decision") or {}
    results = enrichment.get("results", [])
    remote = [r for r in results if r.get("provider") != "local_ioc" and r.get("status") == "ok"]
    cache_mode = "warm" if any(r.get("from_cache") for r in remote) else "cold"
    decided = timings.get("decided_at") if decision.get("approval") in ("approved", "rejected") else None
    return {
        "case_id": snapshot["case_id"],
        "source_type": snapshot["source"]["type"],
        "scenario": snapshot.get("labels", {}).get("scenario", ""),
        "score": score.get("total"),
        "band": score.get("band"),
        "enrichment_mode": enrichment.get("enrichment_mode"),
        "cache_mode": cache_mode,
        "processing_seconds": _seconds(timings.get("received_at"), timings.get("card_ready_at")),
        "analyst_active_seconds": decision.get("analyst_active_seconds"),
        "approval_wait_seconds": _seconds(timings.get("card_ready_at"), decided),
        "response_seconds": _seconds(decided, timings.get("response_verified_at")),
        "time_to_triage_seconds": _seconds(timings.get("received_at"), decided),
        "time_to_contain_seconds": _seconds(timings.get("received_at"), timings.get("response_verified_at")),
        "outcome": snapshot.get("outcome") or snapshot.get("status"),
        "duplicate": len(snapshot.get("duplicates", [])),
        "error_count": sum(1 for e in events if e.get("event_type") == "error"),
    }


def collect(data_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for case_file in sorted(Path(data_dir, "cases").glob("*/case.json")):
        snapshot = json.loads(case_file.read_text(encoding="utf-8"))
        events_path = case_file.parent / "events.jsonl"
        events = []
        if events_path.exists():
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line]
        rows.append(case_row(snapshot, events))
    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize(rows: list[dict[str, Any]], column: str) -> dict[str, Any]:
    values = [r[column] for r in rows if isinstance(r.get(column), (int, float))]
    if not values:
        return {"n": 0, "median": None, "min": None, "max": None}
    return {"n": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}
