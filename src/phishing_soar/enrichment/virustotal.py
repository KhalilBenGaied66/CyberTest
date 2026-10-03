"""Optional VirusTotal v3 *report lookup* adapter (``VT_ENABLED=false`` by default).

Never uploads files or submits URLs for scanning: it only GETs existing
reports. Quota is enforced locally by the engine (3/min, 100/day by default),
below the public API's documented default limit.
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

from ..models import Indicator
from .base import Answer, HttpRequest, Provider, ProviderResponseError

API_BASE = "https://www.virustotal.com/api/v3/"
HIGH_DETECTIONS = 5


class VirusTotalProvider(Provider):
    name = "virustotal"
    supported_types = frozenset({"ip", "domain", "url", "sha256"})
    no_result_on_404 = True

    @property
    def cache_ttl_seconds(self) -> int:
        return self.settings.vt_cache_ttl_seconds

    def missing_configuration(self) -> str | None:
        if not self.settings.vt_enabled:
            return "disabled"
        return None if self.settings.vt_api_key else "not_configured"

    def build_request(self, indicator: Indicator) -> HttpRequest:
        value = indicator.normalized_value
        if indicator.type == "sha256":
            path = f"files/{value}"
        elif indicator.type == "domain":
            path = f"domains/{quote(value, safe='')}"
        elif indicator.type == "ip":
            path = f"ip_addresses/{quote(value, safe='')}"
        else:
            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            path = f"urls/{url_id}"
        headers = {"x-apikey": self.settings.vt_api_key or "", "Accept": "application/json"}
        return self.request("GET", API_BASE + path, headers, None)

    def interpret(self, indicator: Indicator, payload: Any) -> Answer:
        try:
            stats = payload["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderResponseError("missing last_analysis_stats") from exc
        details = {k: stats.get(k) for k in ("malicious", "suspicious", "harmless", "undetected")}
        if malicious >= HIGH_DETECTIONS:
            return Answer(match=True, verdict="malicious", confidence=None, details=details)
        if malicious > 0:
            return Answer(match=True, verdict="suspicious", details=details)
        return Answer(match=False, verdict="no_detections", details=details)
