"""Command-line entry point: ``phishing-soar <command>`` or ``python -m phishing_soar``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .audit import verify_chain
from .config import Policy, Settings
from .enrichment.base import offline_transport
from .enrichment.replay import ReplayTransport
from .metrics import COLUMNS, collect, summarize, write_csv
from .pipeline import SoarPipeline


def _print(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    changes: dict[str, Any] = {}
    if args.data_dir:
        changes["data_dir"] = Path(args.data_dir)
    if args.policy:
        changes["policy"] = Policy.from_file(args.policy)
    if args.offline:
        changes["offline"] = True
    return settings.with_overrides(**changes) if changes else settings


def _pipeline(args: argparse.Namespace) -> SoarPipeline:
    settings = _settings(args)
    transport = None
    if args.replay:
        transport = ReplayTransport(args.replay)
    elif settings.offline:
        transport = offline_transport
    return SoarPipeline(settings, transport=transport)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishing-soar", description=__doc__)
    parser.add_argument("--data-dir", help="runtime data directory (default $SOAR_DATA_DIR or data/runtime)")
    parser.add_argument("--policy", help="lab policy JSON (default $SOAR_POLICY_FILE)")
    parser.add_argument("--offline", action="store_true", help="disable all remote enrichment")
    parser.add_argument("--replay", help="serve provider responses from a replay manifest (demos/tests)")
    sub = parser.add_subparsers(dest="command", required=True)

    email = sub.add_parser("ingest-email", help="submit one .eml file")
    email.add_argument("path")
    email.add_argument("--reporter")
    email.add_argument("--reported-at")
    email.add_argument("--scenario", help="metrics label, e.g. P1")

    wazuh = sub.add_parser("ingest-wazuh", help="submit one Wazuh alert JSON file")
    wazuh.add_argument("path")
    wazuh.add_argument("--scenario")

    decide = sub.add_parser("decide", help="record an analyst decision")
    decide.add_argument("case_id")
    decide.add_argument("--token", required=True)
    decide.add_argument("--decision", choices=("approve", "reject"), required=True)
    decide.add_argument("--verdict", required=True, choices=("malicious", "benign", "suspicious_no_action"))
    decide.add_argument("--reason", required=True)
    decide.add_argument("--analyst", required=True)
    decide.add_argument("--action", action="append", default=[], help="approved action_id (repeatable)")
    decide.add_argument("--active-seconds", type=float, help="analyst hands-on time for metrics")

    sub.add_parser("sweep-timeouts", help="time out overdue approvals (no containment)")
    sub.add_parser("expire", help="remove expired temporary blocks")
    rollback = sub.add_parser("rollback", help="manually remove a block by action_id or rollback_id")
    rollback.add_argument("id")
    rollback.add_argument("--analyst", required=True)
    rollback.add_argument("--reason", required=True)

    show = sub.add_parser("show-case", help="print a case snapshot")
    show.add_argument("case_id")
    audit = sub.add_parser("verify-audit", help="recompute the audit hash chain")
    audit.add_argument("--audit-dir")
    metrics = sub.add_parser("metrics", help="export per-case metrics")
    metrics.add_argument("--out", help="CSV output path")

    serve = sub.add_parser("serve", help="run the authenticated HTTP API for Shuffle")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8088)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command
    if command == "verify-audit":
        audit_dir = Path(args.audit_dir) if args.audit_dir else _settings(args).data_dir / "audit"
        report = verify_chain(audit_dir)
        _print(report)
        return 0 if report["ok"] else 1
    if command == "metrics":
        rows = collect(_settings(args).data_dir)
        if args.out:
            write_csv(rows, Path(args.out))
        _print({"rows": len(rows), "columns": list(COLUMNS),
                "processing_seconds": summarize(rows, "processing_seconds"),
                "analyst_active_seconds": summarize(rows, "analyst_active_seconds"),
                "time_to_triage_seconds": summarize(rows, "time_to_triage_seconds")})
        return 0

    pipeline = _pipeline(args)
    if command == "ingest-email":
        labels = {"scenario": args.scenario} if args.scenario else None
        _print(pipeline.ingest_email(Path(args.path).read_bytes(), reporter=args.reporter,
                                     reported_at=args.reported_at, labels=labels))
    elif command == "ingest-wazuh":
        labels = {"scenario": args.scenario} if args.scenario else None
        _print(pipeline.ingest_wazuh(Path(args.path).read_bytes(), labels=labels))
    elif command == "decide":
        payload = {"decision": args.decision, "verdict": args.verdict, "reason": args.reason,
                   "analyst": args.analyst, "approved_actions": args.action}
        if args.active_seconds is not None:
            payload["analyst_active_seconds"] = args.active_seconds
        _print(pipeline.decide(args.case_id, args.token, payload))
    elif command == "sweep-timeouts":
        _print({"handled": pipeline.sweep_timeouts()})
    elif command == "expire":
        _print({"handled": pipeline.run_expiry()})
    elif command == "rollback":
        _print(pipeline.rollback(args.id, analyst=args.analyst, reason=args.reason))
    elif command == "show-case":
        _print(pipeline.load_case(args.case_id))
    elif command == "serve":
        from .service import build_server

        server = build_server(pipeline, args.host, args.port)
        sys.stderr.write(f"phishing-soar API listening on http://{args.host}:{args.port}\n")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
