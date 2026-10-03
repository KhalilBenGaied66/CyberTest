#!/usr/bin/env python3
"""Wazuh custom integration: forward selected auth / malicious-IP alerts to Shuffle.

Installed as /var/ossec/integrations/custom-soar.py (see ossec-integration.example.xml).
integratord calls it as:  custom-soar <alert_file> <api_key> <hook_url> [debug]

Only an allowlisted subset of alert fields is forwarded (data minimisation), wrapped
in the lab envelope the SOAR normalizer expects. Network or HTTP failures are logged
and never retried in a tight loop; the alert remains in alerts.json for replay.
"""

import json
import sys
import time
import urllib.error
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECONDS = 10
MAX_LOG_CHARS = 2048
MAX_PREVIOUS_OUTPUT_CHARS = 16384


def log(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} custom-soar: {message}\n")
    except OSError:
        pass


def pick(source, keys):
    return {k: source[k] for k in keys if isinstance(source, dict) and k in source}


def select_fields(alert):
    data = alert.get("data") or {}
    selected = {
        "id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule": pick(alert.get("rule") or {}, ("id", "level", "description", "groups", "firedtimes", "frequency")),
        "agent": pick(alert.get("agent") or {}, ("id", "name", "ip")),
        "manager": pick(alert.get("manager") or {}, ("name",)),
        "data": pick(data, ("srcip", "srcport", "dstuser", "srcuser", "authentication_failures_5m",
                            "distinct_users_5m", "success_after_failures")),
    }
    win = (data.get("win") or {}).get("eventdata") if isinstance(data.get("win"), dict) else None
    if isinstance(win, dict):
        selected["data"]["win"] = {"eventdata": pick(win, ("ipAddress", "targetUserName", "logonType"))}
    if alert.get("full_log"):
        selected["full_log"] = str(alert["full_log"])[:MAX_LOG_CHARS]
    if alert.get("previous_output"):
        selected["previous_output"] = str(alert["previous_output"])[:MAX_PREVIOUS_OUTPUT_CHARS]
    return selected


def main(argv):
    if len(argv) < 4:
        log("usage: custom-soar <alert_file> <api_key> <hook_url>")
        return 1
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    try:
        with open(alert_file, encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"cannot read alert file: {exc}")
        return 1
    if not isinstance(alert.get("rule"), dict) or not alert["rule"].get("id"):
        log("alert without rule.id ignored")
        return 0
    envelope = {
        "schema_version": "1.0",
        "source": "wazuh",
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alert": select_fields(alert),
    }
    request = urllib.request.Request(
        hook_url,
        data=json.dumps(envelope).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            log(f"forwarded alert {alert.get('id')} rule {alert['rule'].get('id')}: HTTP {response.status}")
            return 0
    except urllib.error.HTTPError as exc:
        log(f"HTTP {exc.code} forwarding alert {alert.get('id')}")
    except (urllib.error.URLError, OSError) as exc:
        log(f"network error forwarding alert {alert.get('id')}: {exc}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
