#!/usr/bin/env python3
"""Refresh the local IOC mirror from the ThreatFox JSON export (scheduled job).

Keeps the last-known-good mirror when the download or conversion fails and
records the outcome and feed age in a status file next to the mirror. Point
SOAR_IOC_PATHS at both the committed seed and the generated mirror.

    THREATFOX_AUTH_KEY=... python scripts/refresh_ioc_mirror.py --out data/ioc/threatfox_mirror.jsonl
    python scripts/refresh_ioc_mirror.py --input export.json --out data/ioc/threatfox_mirror.jsonl   # offline

The export URL and its authentication requirements are set by abuse.ch and can
change; check the current ThreatFox export documentation before scheduling this.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from phishing_soar.enrichment.mirror import convert_threatfox_export, to_jsonl  # noqa: E402
from phishing_soar.util import iso, write_json_atomic, write_text_atomic  # noqa: E402

DEFAULT_URL = "https://threatfox.abuse.ch/export/json/recent/"
MAX_BYTES = 200 * 1024 * 1024


def download(url: str, auth_key: str | None) -> bytes:
    headers = {"User-Agent": "phishing-soar-lab/0.1 (mirror refresh)"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("export larger than the configured limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--input", type=Path, help="convert a previously downloaded export instead of downloading")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--ttl-days", type=int, default=7)
    parser.add_argument("--min-confidence", type=int, default=50)
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    status_path = args.out.with_suffix(".status.json")
    status = {"attempted_at": iso(now), "source": str(args.input or args.url)}
    try:
        raw = args.input.read_bytes() if args.input else download(args.url, os.environ.get("THREATFOX_AUTH_KEY"))
        entries, counters = convert_threatfox_export(json.loads(raw), now=now, ttl_days=args.ttl_days,
                                                     min_confidence=args.min_confidence)
        if not entries:
            raise ValueError("export produced no usable entries; keeping last-known-good mirror")
        write_text_atomic(args.out, to_jsonl(entries))
        status.update({"result": "ok", "refreshed_at": iso(now), **counters})
        code = 0
    except Exception as exc:  # any failure keeps the previous mirror
        status.update({"result": "failed", "error": f"{type(exc).__name__}: {exc}"[:500]})
        if args.out.exists():
            age = now.timestamp() - args.out.stat().st_mtime
            status["last_known_good_age_hours"] = round(age / 3600, 1)
        code = 1
    write_json_atomic(status_path, status)
    print(json.dumps(status, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
