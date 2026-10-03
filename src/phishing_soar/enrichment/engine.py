"""Enrichment orchestration.

Order for every indicator: (1) scope check, (2) local IOC exact lookup -- always,
(3) unexpired SQLite cache, (4) URLhaus / ThreatFox if allowed, (5) optional
VirusTotal within budget. Remote failures become ``unknown`` and are never
treated as clean.
"""

from __future__ import annotations

import email.utils
import json
import random
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..config import Settings
from ..models import EnrichmentResult, Indicator
from ..state import StateStore
from ..util import iso, sha256_hex, utcnow
from .base import Answer, Provider, ProviderResponseError, Transport, TransportError, urllib_transport
from .local_ioc import LocalIocIndex
from .threatfox import ThreatFoxProvider
from .urlhaus import UrlhausProvider
from .virustotal import VirusTotalProvider

REMOTE_PROVIDERS = ("urlhaus", "threatfox", "virustotal")


@dataclass
class EnrichmentReport:
    results: list[EnrichmentResult]
    provider_health: dict[str, str]
    provider_reasons: dict[str, list[str]]
    completeness_ratio: float
    completeness: str  # complete | partial | local_only
    enrichment_mode: str  # online | degraded | offline
    local_feed_age_hours: float | None
    local_load_warnings: list[str] = field(default_factory=list)
    cache_hits: int = 0

    def for_indicator(self, indicator_id: str) -> list[EnrichmentResult]:
        return [r for r in self.results if r.indicator_id == indicator_id]

    def health_summary(self) -> dict[str, Any]:
        return {
            **self.provider_health,
            "local_feed_age_hours": self.local_feed_age_hours,
            "completeness": self.completeness,
            "completeness_ratio": self.completeness_ratio,
            "enrichment_mode": self.enrichment_mode,
            "cache_hits": self.cache_hits,
        }

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["results"] = [r.to_dict() for r in self.results]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnrichmentReport:
        values = dict(data)
        values["results"] = [EnrichmentResult.from_dict(r) for r in data["results"]]
        return cls(**values)


def _retry_after_seconds(headers: dict[str, str], now: datetime) -> int:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    seconds = 60
    if value:
        value = value.strip()
        if value.isdigit():
            seconds = int(value)
        else:
            try:
                seconds = int((email.utils.parsedate_to_datetime(value) - now).total_seconds())
            except (TypeError, ValueError):
                seconds = 60
    return max(1, min(seconds, 3600))


class Enricher:
    def __init__(
        self,
        settings: Settings,
        state: StateStore,
        local_index: LocalIocIndex,
        *,
        transport: Transport | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
        raw_dir: Path | None = None,
    ) -> None:
        self.settings = settings
        self.state = state
        self.local = local_index
        self.transport = transport or urllib_transport
        self.clock = clock
        self.sleep = sleep
        self.rng = rng
        self.raw_dir = raw_dir
        self.providers: list[Provider] = [UrlhausProvider(settings), ThreatFoxProvider(settings)]
        if settings.vt_enabled:
            self.providers.append(VirusTotalProvider(settings))

    def enrich(self, indicators: list[Indicator]) -> EnrichmentReport:
        now = self.clock()
        results: list[EnrichmentResult] = []
        for indicator in indicators:
            results.append(self.local.lookup(indicator, now))
            for provider in self.providers:
                results.append(self._lookup(provider, indicator, now))
        return self._report(results, now)

    # -- single lookup ------------------------------------------------------------------------

    def _result(self, provider: str, indicator: Indicator, now: datetime, **kwargs: Any) -> EnrichmentResult:
        return EnrichmentResult(
            provider=provider,
            indicator_id=indicator.indicator_id,
            indicator_type=indicator.type,
            indicator_value=indicator.normalized_value,
            fetched_at=iso(now),
            **kwargs,
        )

    def _unknown(self, provider: Provider, indicator: Indicator, now: datetime, reason: str,
                 details: dict[str, Any] | None = None) -> EnrichmentResult:
        return self._result(provider.name, indicator, now, status="unknown", match=None, verdict=None,
                            reason=reason, details=details or {})

    def _failure(self, provider: Provider, now: datetime) -> bool:
        """Record a failure; True when this failure opened the provider's circuit."""
        return self.state.record_failure(
            provider.name, now,
            threshold=self.settings.circuit_failure_threshold,
            window=self.settings.circuit_window_seconds,
            open_seconds=self.settings.circuit_open_seconds,
        )

    def _store_raw(self, body: bytes) -> str:
        digest = sha256_hex(body)
        if self.raw_dir is not None:
            path = self.raw_dir / f"{digest}.json"
            if not path.exists():
                self.raw_dir.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
        return f"sha256:{digest}"

    def _lookup(self, provider: Provider, indicator: Indicator, now: datetime) -> EnrichmentResult:
        if indicator.type not in provider.supported_types:
            return self._result(provider.name, indicator, now, status="not_applicable", match=None,
                                verdict=None, reason="unsupported_type")
        if not indicator.external_lookup_allowed:
            return self._result(provider.name, indicator, now, status="skipped", match=None,
                                verdict=None, reason=f"scope:{indicator.scope}")
        if self.settings.offline:
            return self._unknown(provider, indicator, now, "offline")
        missing = provider.missing_configuration()
        if missing:
            return self._unknown(provider, indicator, now, missing)
        cached = self.state.cache_get(provider.name, indicator.type, indicator.normalized_value, now)
        if cached is not None:
            result = EnrichmentResult.from_dict(cached)
            result.indicator_id = indicator.indicator_id
            result.from_cache = True
            return result
        open_until = self.state.circuit_open_until(provider.name, now)
        if open_until is not None:
            return self._unknown(provider, indicator, now, "circuit_open", {"open_until": iso(open_until)})
        if provider.name == "virustotal" and not self.state.try_consume_vt(
            now, self.settings.vt_per_minute, self.settings.vt_per_day
        ):
            return self._unknown(provider, indicator, now, "budget_exhausted")

        request = provider.build_request(indicator)
        answer: Answer | None = None
        raw_ref: str | None = None
        for attempt in (1, 2):
            try:
                response = self.transport(request)
            except TransportError as exc:
                opened = self._failure(provider, now)
                if attempt == 1 and not opened and exc.kind in ("timeout", "connection"):
                    self.sleep(0.5 + self.rng() * 0.5)
                    continue
                return self._unknown(provider, indicator, now, exc.kind)
            if response.status == 429:
                wait = _retry_after_seconds(response.headers, now)
                self.state.open_circuit(provider.name, now + timedelta(seconds=wait), "rate_limited")
                return self._unknown(provider, indicator, now, "rate_limited", {"retry_after_seconds": wait})
            if response.status == 404 and provider.no_result_on_404:
                answer = Answer(match=False, verdict="no_result")
                break
            if response.status >= 500:
                opened = self._failure(provider, now)
                if attempt == 1 and not opened:
                    self.sleep(0.5 + self.rng() * 0.5)
                    continue
                return self._unknown(provider, indicator, now, f"http_{response.status}")
            if not 200 <= response.status < 300:
                self._failure(provider, now)
                reason = "auth_error" if response.status in (401, 403) else f"http_{response.status}"
                return self._unknown(provider, indicator, now, reason)
            try:
                payload = json.loads(response.body.decode("utf-8"))
                answer = provider.interpret(indicator, payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ProviderResponseError) as exc:
                self._failure(provider, now)
                return self._unknown(provider, indicator, now, "malformed_response", {"error": str(exc)[:200]})
            raw_ref = self._store_raw(response.body)
            break
        if answer is None:  # pragma: no cover - loop always returns or breaks
            return self._unknown(provider, indicator, now, "no_answer")
        self.state.record_success(provider.name)
        ttl = provider.cache_ttl_seconds
        result = self._result(
            provider.name, indicator, now, status="ok", match=answer.match, verdict=answer.verdict,
            confidence=answer.confidence, details=answer.details,
            expires_at=iso(now + timedelta(seconds=ttl)), raw_ref=raw_ref,
        )
        self.state.cache_put(provider.name, indicator.type, indicator.normalized_value,
                             result.to_dict(), now, ttl)
        return result

    # -- aggregate ----------------------------------------------------------------------------

    def _report(self, results: list[EnrichmentResult], now: datetime) -> EnrichmentReport:
        applicable = [r for r in results if r.status in ("ok", "unknown")]
        answered = [r for r in applicable if r.status == "ok"]
        remote = [r for r in applicable if r.provider != "local_ioc"]
        remote_answered = [r for r in remote if r.status == "ok"]
        ratio = round(len(answered) / len(applicable), 3) if applicable else 1.0
        if remote and not remote_answered:
            completeness = "local_only"
        elif ratio >= 0.8:
            completeness = "complete"
        elif ratio >= 0.4:
            completeness = "partial"
        else:
            completeness = "local_only"
        if self.settings.offline or (remote and not remote_answered):
            mode = "offline"
        elif len(remote_answered) < len(remote):
            mode = "degraded"
        else:
            mode = "online"

        health: dict[str, str] = {"local_ioc": "ok" if self.local.loaded_files else "missing"}
        reasons: dict[str, list[str]] = {}
        for name in REMOTE_PROVIDERS:
            if name == "virustotal" and not self.settings.vt_enabled:
                health[name] = "disabled"
                continue
            mine = [r for r in results if r.provider == name and r.status in ("ok", "unknown")]
            unknown = Counter(r.reason or "unknown" for r in mine if r.status == "unknown")
            if unknown:
                reasons[name] = sorted(unknown)
            if not mine:
                health[name] = "not_applicable"
            elif not unknown:
                health[name] = "ok"
            elif len(unknown) and sum(unknown.values()) == len(mine):
                health[name] = "unavailable"
            else:
                health[name] = "degraded"
        return EnrichmentReport(
            results=results,
            provider_health=health,
            provider_reasons=reasons,
            completeness_ratio=ratio,
            completeness=completeness,
            enrichment_mode=mode,
            local_feed_age_hours=self.local.feed_age_hours(now),
            local_load_warnings=list(self.local.load_warnings),
            cache_hits=sum(1 for r in results if r.from_cache),
        )
