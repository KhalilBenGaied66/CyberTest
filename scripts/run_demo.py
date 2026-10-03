#!/usr/bin/env python3
"""Run the deterministic portfolio demos end to end.

No network, a fixed clock, and recorded provider answers, so the scores are
reproducible: P1 74 HIGH, P2 53 MEDIUM, P3 5 LOW, W1 90 HIGH and P1 offline
69 HIGH (local_only). Every path ends in an audited terminal state and the
hash chain is verified at the end.

    python scripts/run_demo.py                 # temp data dir, printed summary
    python scripts/run_demo.py --data-dir data/demo --check
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from phishing_soar.audit import verify_chain  # noqa: E402
from phishing_soar.config import Policy, Settings  # noqa: E402
from phishing_soar.enrichment.replay import ReplayTransport  # noqa: E402
from phishing_soar.pipeline import SoarPipeline  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures"
MANIFEST = FIXTURES / "provider_responses" / "manifest.json"
EXPECTED = {"W1": 90, "P3": 5, "P2": 53, "P1": 74, "P1-offline": 69}


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 3, 7, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def make_pipeline(data_dir: Path, clock: Clock, *, offline: bool = False) -> SoarPipeline:
    settings = Settings(
        data_dir=data_dir,
        ioc_paths=(FIXTURES / "local_iocs.jsonl",),
        policy=Policy.from_file(REPO / "config" / "lab-policy.json"),
        lab_doc_ranges_routable=True,
        urlhaus_auth_key="replay-only",
        threatfox_auth_key="replay-only",
    )
    transport = ReplayTransport(MANIFEST, fail_with="timeout" if offline else None)
    return SoarPipeline(settings, transport=transport, clock=clock, sleep=lambda _: None)


def decide(pipeline: SoarPipeline, created: dict, decision: str, verdict: str, reason: str, *, contain: bool = True) -> dict:
    actions = [a["action_id"] for a in created["proposed_actions"]] if contain and decision == "approve" else []
    return pipeline.decide(created["case_id"], created["approval"]["token"], {
        "decision": decision, "verdict": verdict, "reason": reason, "analyst": "analyst-lab",
        "approved_actions": actions,
    })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", help="where to write runtime data (default: a new temp dir)")
    parser.add_argument("--check", action="store_true", help="exit 1 if any score differs from the expected value")
    parser.add_argument("--show-card", action="store_true", help="print the W1 analyst card")
    args = parser.parse_args()
    root = Path(args.data_dir) if args.data_dir else Path(tempfile.mkdtemp(prefix="phishing-soar-demo-"))
    clock = Clock()
    online = make_pipeline(root / "online", clock)
    offline = make_pipeline(root / "offline", clock, offline=True)
    rows = []

    def record(name: str, created: dict, outcome: dict | None, note: str = "") -> None:
        snapshot = (online if name != "P1-offline" else offline).load_case(created["case_id"])
        rows.append({
            "scenario": name,
            "case": created["case_id"][:8],
            "score": f"{created['score']['total']} {created['score']['band'].upper()}",
            "enrichment": f"{created['enrichment']['mode']}/{created['enrichment']['completeness']}",
            "decision": (snapshot.get("decision") or {}).get("approval", "-"),
            "outcome": snapshot.get("outcome") or snapshot["status"],
            "actions": ", ".join(f"{a['type']}:{a['result']}" for a in snapshot["actions"]) or "none",
            "note": note,
        })

    # Approve: W1 -> 90 -> approval -> simulated block -> accelerated expiry -> add/delete receipts
    w1 = online.ingest_wazuh((FIXTURES / "wazuh" / "w1_bruteforce_success.json").read_bytes(), labels={"scenario": "W1"})
    if args.show_card:
        print(w1["card"], end="\n\n")
    clock.advance(minutes=2)
    w1_out = decide(online, w1, "approve", "malicious", "Brute force followed by privileged login; exact IOC corroborated")
    clock.advance(minutes=60)
    expired = online.run_expiry()
    record("W1", w1, w1_out, f"expiry removed {len(expired)} block(s)")

    # Reject: P3 -> 5 -> benign -> no containment -> closure
    p3 = online.ingest_email((FIXTURES / "eml" / "p3_benign_saas.eml").read_bytes(),
                             reporter="alex.analyst@lab.example", labels={"scenario": "P3"})
    clock.advance(minutes=1)
    record("P3", p3, decide(online, p3, "reject", "benign", "Legitimate SaaS notification; sending platform expected"))

    # Medium malicious with no blockable target: P2
    p2 = online.ingest_email((FIXTURES / "eml" / "p2_malicious_attachment.eml").read_bytes(), labels={"scenario": "P2"})
    clock.advance(minutes=3)
    record("P2", p2, decide(online, p2, "approve", "malicious", "Macro dropper hash confirmed by two sources"),
           "auth pass != benign")

    # Approve: P1 credential harvest
    p1_raw = (FIXTURES / "eml" / "p1_credential_harvest.eml").read_bytes()
    p1 = online.ingest_email(p1_raw, reporter="alex.analyst@lab.example", labels={"scenario": "P1"})
    clock.advance(minutes=2)
    record("P1", p1, decide(online, p1, "approve", "malicious", "Punycode credential page; exact URL match; DMARC fail"))

    # Duplicate and malformed paths
    duplicate = online.ingest_email(p1_raw)
    truncated = online.ingest_email((FIXTURES / "eml" / "p1_truncated.eml").read_bytes(), labels={"scenario": "P1-truncated"})
    clock.advance(minutes=31)
    online.sweep_timeouts()
    record("P1-truncated", truncated, None, "parse_partial, left undecided -> timeout")

    # API failure / offline IOC fallback, then analyst timeout
    p1_offline = offline.ingest_email(p1_raw, labels={"scenario": "P1-offline"})
    clock.advance(minutes=31)
    offline.sweep_timeouts()
    record("P1-offline", p1_offline, None, "providers timed out; left undecided -> timeout")

    header = ["scenario", "case", "score", "enrichment", "decision", "outcome", "actions", "note"]
    widths = {h: max(len(h), *(len(str(r[h])) for r in rows)) for h in header}
    print("  ".join(h.ljust(widths[h]) for h in header))
    for row in rows:
        print("  ".join(str(row[h]).ljust(widths[h]) for h in header))
    print(f"\nduplicate P1 -> {duplicate['result']} (linked to {duplicate['case_id'][:8]}, occurrence {duplicate['occurrence']})")

    ok = True
    for pipeline, label in ((online, "online"), (offline, "offline")):
        report = verify_chain(pipeline.root / "audit")
        ok &= report["ok"]
        print(f"audit chain [{label}]: {'OK' if report['ok'] else 'BROKEN'} ({report['events']} events, {report['cases']} cases)")
    print(f"runtime data: {root}")

    scores = {r["scenario"]: int(r["score"].split()[0]) for r in rows}
    mismatches = {k: (scores.get(k), v) for k, v in EXPECTED.items() if scores.get(k) != v}
    if mismatches:
        print(f"score mismatches (got, expected): {mismatches}")
    return 1 if args.check and (mismatches or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
