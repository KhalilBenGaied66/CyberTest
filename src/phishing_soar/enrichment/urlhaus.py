"""URLhaus (abuse.ch) adapter: exact URL, host and payload-hash lookups.

Request/response shapes follow the URLhaus v1 API (``/v1/url/``, ``/v1/host/``,
``/v1/payload/``, ``Auth-Key`` header). Recheck against the current API
documentation before enabling it against the live service.

Only exact URL and payload-hash hits count as ``malicious``. A host lookup hit
means *some* URL on that host distributed malware, which is common on shared
infrastructure, so it is reported as ``suspicious`` context only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from ..models import Indicator
from .base import Answer, HttpRequest, Provider, ProviderResponseError

BASE_URL = "https://urlhaus-api.abuse.ch/v1/"
_ENDPOINTS = {
    "url": ("url/", "url"),
    "domain": ("host/", "host"),
    "ip": ("host/", "host"),
    "sha256": ("payload/", "sha256_hash"),
}
_NO_RESULT = frozenset({"no_results", "no_result"})


class UrlhausProvider(Provider):
    name = "urlhaus"
    supported_types = frozenset(_ENDPOINTS)

    def missing_configuration(self) -> str | None:
        return None if self.settings.urlhaus_auth_key else "not_configured"

    def build_request(self, indicator: Indicator) -> HttpRequest:
        path, field = _ENDPOINTS[indicator.type]
        body = urlencode({field: indicator.normalized_value}).encode("ascii")
        headers = {
            "Auth-Key": self.settings.urlhaus_auth_key or "",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        return self.request("POST", BASE_URL + path, headers, body)

    def interpret(self, indicator: Indicator, payload: Any) -> Answer:
        if not isinstance(payload, dict) or "query_status" not in payload:
            raise ProviderResponseError("missing query_status")
        status = str(payload["query_status"])
        if status in _NO_RESULT:
            return Answer(match=False, verdict="no_result")
        if status != "ok":
            raise ProviderResponseError(f"query_status={status}")
        reference = payload.get("urlhaus_reference")
        if indicator.type == "url":
            return Answer(
                match=True, verdict="malicious",
                details={
                    "url_status": payload.get("url_status"),
                    "threat": payload.get("threat"),
                    "tags": payload.get("tags") or [],
                    "blacklists": payload.get("blacklists") or {},
                    "date_added": payload.get("date_added"),
                    "reference": reference,
                },
            )
        if indicator.type == "sha256":
            return Answer(
                match=True, verdict="malicious",
                details={
                    "file_type": payload.get("file_type"),
                    "signature": payload.get("signature"),
                    "firstseen": payload.get("firstseen"),
                    "url_count": payload.get("url_count"),
                },
            )
        return Answer(
            match=True, verdict="suspicious",
            details={
                "scope": "host_has_listed_urls",
                "url_count": payload.get("url_count"),
                "blacklists": payload.get("blacklists") or {},
                "reference": reference,
            },
        )
