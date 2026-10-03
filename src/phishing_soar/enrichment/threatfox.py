"""ThreatFox (abuse.ch) adapter: IOC search for IPs, domains, URLs and hashes.

Uses ``POST /api/v1/`` with ``{"query": "search_ioc", "search_term": ...}`` and
an ``Auth-Key`` header. Results are filtered client-side for an *exact* match
(IPs match ``ip`` or ``ip:port`` entries). Recheck against the current API
documentation before enabling it against the live service.
"""

from __future__ import annotations

import json
from typing import Any

from ..canonical import IndicatorError, canonical_url
from ..models import Indicator
from .base import Answer, HttpRequest, Provider, ProviderResponseError

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALICIOUS_CONFIDENCE = 50


def _exact(indicator: Indicator, ioc: str) -> bool:
    value = indicator.normalized_value
    ioc = ioc.strip()
    if indicator.type == "ip":
        if ioc == value:
            return True
        host, sep, port = ioc.rpartition(":")
        return bool(sep) and port.isdigit() and host.strip("[]") == value
    if indicator.type == "domain":
        return ioc.lower().rstrip(".") == value
    if indicator.type == "sha256":
        return ioc.lower() == value
    if indicator.type == "url":
        try:
            return canonical_url(ioc).normalized == value
        except IndicatorError:
            return False
    return False


class ThreatFoxProvider(Provider):
    name = "threatfox"
    supported_types = frozenset({"ip", "domain", "url", "sha256"})

    def missing_configuration(self) -> str | None:
        return None if self.settings.threatfox_auth_key else "not_configured"

    def build_request(self, indicator: Indicator) -> HttpRequest:
        body = json.dumps({"query": "search_ioc", "search_term": indicator.normalized_value})
        headers = {
            "Auth-Key": self.settings.threatfox_auth_key or "",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return self.request("POST", API_URL, headers, body.encode("utf-8"))

    def interpret(self, indicator: Indicator, payload: Any) -> Answer:
        if not isinstance(payload, dict) or "query_status" not in payload:
            raise ProviderResponseError("missing query_status")
        status = str(payload["query_status"])
        if status in ("no_result", "no_results"):
            return Answer(match=False, verdict="no_result")
        if status != "ok":
            raise ProviderResponseError(f"query_status={status}")
        data = payload.get("data")
        if not isinstance(data, list):
            raise ProviderResponseError("data is not a list")
        exact = [row for row in data if isinstance(row, dict) and _exact(indicator, str(row.get("ioc", "")))]
        if not exact:
            return Answer(match=False, verdict="no_result", details={"non_exact_results": len(data)})
        confidence = max(int(row.get("confidence_level") or 0) for row in exact)
        return Answer(
            match=True,
            verdict="malicious" if confidence >= MALICIOUS_CONFIDENCE else "suspicious",
            confidence=confidence,
            details={
                "ioc_ids": [row.get("id") for row in exact][:10],
                "threat_types": sorted({str(row.get("threat_type")) for row in exact}),
                "malware": sorted({str(row.get("malware_printable") or row.get("malware")) for row in exact}),
                "first_seen": min(str(row.get("first_seen") or "") for row in exact) or None,
                "last_seen": max(str(row.get("last_seen") or "") for row in exact) or None,
                "references": [f"https://threatfox.abuse.ch/ioc/{row.get('id')}/" for row in exact][:5],
            },
        )
