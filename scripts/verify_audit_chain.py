#!/usr/bin/env python3
"""Recompute the audit ledger hash chain (schedule nightly). Exit code 1 on any break.

    python scripts/verify_audit_chain.py data/runtime/audit
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from phishing_soar.audit import verify_chain  # noqa: E402


def main() -> int:
    audit_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "data" / "runtime" / "audit"
    report = verify_chain(audit_dir)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
