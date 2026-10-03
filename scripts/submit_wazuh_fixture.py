#!/usr/bin/env python3
"""Post a Wazuh alert fixture to the Shuffle WF-WAZUH-INTAKE webhook or the SOAR API.

    SOAR_API_TOKEN=... python scripts/submit_wazuh_fixture.py tests/fixtures/wazuh/w1_bruteforce_success.json \\
        --url http://127.0.0.1:8088/v1/intake/wazuh
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-env", default="SOAR_API_TOKEN")
    args = parser.parse_args()
    payload = json.loads(Path(args.path).read_text(encoding="utf-8"))  # validate before sending
    token = os.environ.get(args.token_env)
    if not token:
        parser.error(f"set {args.token_env}")
    request = urllib.request.Request(args.url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={
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
