#!/usr/bin/env python3
"""Authenticated upload helper: post one .eml file and reporter metadata.

Point --url at the Shuffle WF-EMAIL-INTAKE webhook (JSON mode) or directly at
the SOAR API ``/v1/intake/email``. The bearer token comes from the environment
(``SOAR_API_TOKEN`` by default) so it never appears in shell history.

    SOAR_API_TOKEN=... python scripts/submit_eml.py tests/fixtures/eml/p1_credential_harvest.eml \\
        --url http://127.0.0.1:8088/v1/intake/email --reporter alex.analyst@lab.example
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--url", required=True)
    parser.add_argument("--reporter", required=True)
    parser.add_argument("--reported-at", default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    parser.add_argument("--scenario", help="optional metrics label (P1, P2, ...)")
    parser.add_argument("--token-env", default="SOAR_API_TOKEN")
    args = parser.parse_args()

    raw = Path(args.path).read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        parser.error(f"file must be between 1 byte and {MAX_BYTES} bytes")
    token = os.environ.get(args.token_env)
    if not token:
        parser.error(f"set {args.token_env}")
    body = {"eml_base64": base64.b64encode(raw).decode("ascii"), "reporter": args.reporter,
            "reported_at": args.reported_at}
    if args.scenario:
        body["labels"] = {"scenario": args.scenario}
    request = urllib.request.Request(args.url, data=json.dumps(body).encode("utf-8"), method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(response.read().decode("utf-8"))
            return 0
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
