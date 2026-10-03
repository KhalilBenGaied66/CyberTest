"""Wazuh authentication / malicious-IP alert intake and normalization.

Wazuh field layouts vary by decoder and platform, so every mapping below is
explicit, and missing or unexpected fields become warnings rather than crashes.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .canonical import is_routable
from .config import Policy, Settings
from .indicators import IndicatorCollector
from .models import NormalizedCase
from .util import canonical_json, iso, parse_timestamp, sha256_hex

_USER_RE = re.compile(
    r"(?i)(?:for invalid user|invalid user|for user|user|for)\s+([A-Za-z0-9._@$\\-]{1,64})"
)
_NOT_USERS = frozenset({"from", "invalid", "user", "port", "ssh2"})


class WazuhIntakeError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def load_wazuh_payload(raw: bytes | str | dict[str, Any], *, max_bytes: int) -> tuple[dict, dict]:
    """Return (alert, envelope). Accepts the lab envelope or a bare Wazuh alert."""
    if isinstance(raw, (bytes, str)):
        data_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        if not data_bytes:
            raise WazuhIntakeError("empty_payload")
        if len(data_bytes) > max_bytes:
            raise WazuhIntakeError("payload_too_large", f"{len(data_bytes)} > {max_bytes} bytes")
        try:
            data = json.loads(data_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WazuhIntakeError("invalid_json", type(exc).__name__) from exc
    else:
        data = raw
    if not isinstance(data, dict):
        raise WazuhIntakeError("invalid_payload", "top-level JSON must be an object")
    if isinstance(data.get("alert"), dict):
        alert = data["alert"]
        envelope = {k: v for k, v in data.items() if k != "alert"}
    else:
        alert, envelope = data, {}
    rule = alert.get("rule")
    if not isinstance(rule, dict) or not str(rule.get("id") or "").strip():
        raise WazuhIntakeError("missing_rule_id")
    return alert, envelope


def check_rule_allowed(alert: dict[str, Any], policy: Policy) -> None:
    rule = alert["rule"]
    rule_id = str(rule.get("id")).strip()
    groups = {str(g).lower() for g in rule.get("groups") or [] if isinstance(g, str)}
    if rule_id in policy.wazuh_allowed_rule_ids or groups & set(policy.wazuh_allowed_groups):
        return
    raise WazuhIntakeError("rule_not_allowlisted", f"rule {rule_id}")


def wazuh_dedupe_key(alert: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Stable key: manager + alert ID, falling back to a canonical hash of the alert."""
    manager = ((alert.get("manager") or {}).get("name") or "unknown-manager") if isinstance(
        alert.get("manager"), dict
    ) else "unknown-manager"
    alert_id = str(alert.get("id") or "").strip()
    if alert_id:
        return sha256_hex(f"wazuh|{manager}|{alert_id}"), f"{manager}:{alert_id}", []
    digest = sha256_hex(canonical_json(alert))
    return digest, f"sha256:{digest}", ["missing_alert_id_fallback_hash"]


def _as_int(value: Any, name: str, warnings: list[str]) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        warnings.append(f"non_integer_field:{name}")
        return None


def _as_bool(value: Any, name: str, warnings: list[str]) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    warnings.append(f"non_boolean_field:{name}")
    return None


def normalize_wazuh(
    alert: dict[str, Any],
    envelope: dict[str, Any],
    *,
    case_id: str,
    received_at: str,
    raw_ref: dict[str, Any],
    settings: Settings,
) -> NormalizedCase:
    policy = settings.policy
    warnings: list[str] = []
    rule = alert.get("rule") or {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    if not isinstance(alert.get("data"), dict):
        warnings.append("normalization_warning:missing_data_object")
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    win_event = ((data.get("win") or {}).get("eventdata") or {}) if isinstance(data.get("win"), dict) else {}

    srcip = data.get("srcip") or data.get("src_ip") or win_event.get("ipAddress")
    user = data.get("dstuser") or win_event.get("targetUserName") or data.get("srcuser")
    if not srcip:
        warnings.append("normalization_warning:missing_srcip")
    if not user:
        warnings.append("normalization_warning:missing_user")

    failures = _as_int(data.get("authentication_failures_5m"), "authentication_failures_5m", warnings)
    distinct_users = _as_int(data.get("distinct_users_5m"), "distinct_users_5m", warnings)
    success = _as_bool(data.get("success_after_failures"), "success_after_failures", warnings)
    counts_source = "integration"

    previous = alert.get("previous_output")
    if (failures is None or distinct_users is None) and isinstance(previous, str) and previous.strip():
        lines = [line for line in previous.splitlines() if line.strip()]
        current = str(alert.get("full_log") or "")
        if failures is None:
            failures = len(lines) + (1 if current else 0)
            warnings.append("failure_count_derived_from_previous_output")
        if distinct_users is None:
            users = {
                m.group(1).lower()
                for m in _USER_RE.finditer("\n".join(lines + [current]))
                if m.group(1).lower() not in _NOT_USERS
            }
            if users:
                distinct_users = len(users)
                warnings.append("distinct_users_derived_from_previous_output")
        counts_source = "previous_output"
    rule_id = str(rule.get("id")).strip()
    if success is None and rule_id in policy.wazuh_success_after_failure_rule_ids:
        success = True
    if failures is None and distinct_users is None and success is None:
        counts_source = "unavailable"

    collector = IndicatorCollector(policy, lab_doc_ranges_routable=settings.lab_doc_ranges_routable)
    if srcip:
        indicator = collector.add("ip", str(srcip), origin="wazuh", location="wazuh:data.srcip")
        if indicator and not is_routable(
            indicator.normalized_value, lab_doc_ranges_routable=settings.lab_doc_ranges_routable
        ):
            warnings.append(f"source_ip_not_public:{indicator.scope}")

    observed = parse_timestamp(alert.get("timestamp"))
    if alert.get("timestamp") and observed is None:
        warnings.append("unparseable_timestamp")
    dedupe_key, source_event_id, key_warnings = wazuh_dedupe_key(alert)
    warnings.extend(key_warnings)

    level = _as_int(rule.get("level"), "rule.level", warnings)
    evidence = {
        "wazuh": {
            "manager": (alert.get("manager") or {}).get("name") if isinstance(alert.get("manager"), dict) else None,
            "alert_id": alert.get("id"),
            "rule": {
                "id": rule_id,
                "level": level,
                "description": rule.get("description"),
                "groups": [g for g in rule.get("groups") or [] if isinstance(g, str)],
                "firedtimes": rule.get("firedtimes"),
            },
            "agent": {"id": agent.get("id"), "name": agent.get("name"), "ip": agent.get("ip")},
            "source_ip": str(srcip) if srcip else None,
            "user": str(user) if user else None,
            "behavior": {
                "authentication_failures_5m": failures,
                "distinct_users_5m": distinct_users,
                "success_after_failures": success,
                "counts_source": counts_source,
            },
            "envelope": {
                "schema_version": envelope.get("schema_version"),
                "sent_at": envelope.get("sent_at"),
                "source": envelope.get("source"),
            },
        }
    }
    return NormalizedCase(
        case_id=case_id,
        source_type="wazuh",
        source_event_id=source_event_id,
        received_at=received_at,
        observed_at=iso(observed) if observed else None,
        status="normalized",
        entities={
            "reporter": None,
            "reported_at": None,
            "user": str(user) if user else None,
            "agent": {"id": agent.get("id"), "name": agent.get("name")} if agent else None,
            "sender": None,
        },
        indicators=collector.results(),
        evidence=evidence,
        parse_warnings=warnings + collector.warnings,
        dedupe_key=dedupe_key,
        raw_ref=raw_ref,
    )
