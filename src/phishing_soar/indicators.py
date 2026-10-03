"""Typed, provenance-rich indicator collection shared by both intake sources."""

from __future__ import annotations

from .canonical import (
    IndicatorError,
    UrlParts,
    canonical_domain,
    canonical_email,
    canonical_ip,
    canonical_sha256,
    canonical_url,
    defang,
    domain_display,
    domain_matches,
    ip_in_networks,
    ip_scope,
)
from .config import Policy
from .models import Indicator
from .util import sha256_hex

MAX_VALUE_LENGTH = 2048


class IndicatorCollector:
    """Deduplicates indicators by (type, normalized value) and keeps every occurrence.

    A URL host and the same sender domain stay separate *occurrences* of one
    indicator, so enrichment is performed once while provenance is preserved.
    """

    def __init__(self, policy: Policy, *, lab_doc_ranges_routable: bool) -> None:
        self.policy = policy
        self.lab_doc_ranges_routable = lab_doc_ranges_routable
        self._items: dict[tuple[str, str], Indicator] = {}
        self.warnings: list[str] = []

    def add(
        self,
        ind_type: str,
        value: str,
        *,
        origin: str,
        location: str,
        scoring_eligible: bool = True,
    ) -> Indicator | None:
        value = value[:MAX_VALUE_LENGTH]
        try:
            normalized, display, warning = self._canonicalize(ind_type, value)
        except IndicatorError as exc:
            self.warnings.append(f"indicator_rejected:{ind_type}:{location}:{exc}")
            return None
        key = (ind_type, normalized)
        existing = self._items.get(key)
        if existing is not None:
            if location not in existing.occurrences:
                existing.occurrences.append(location)
            existing.scoring_eligible = existing.scoring_eligible or scoring_eligible
            return existing
        scope, is_public, external_ok, allowlisted = self._classify(ind_type, normalized)
        indicator = Indicator(
            indicator_id="ind-" + sha256_hex(f"{ind_type}|{normalized}")[:16],
            type=ind_type,
            value=value,
            normalized_value=normalized,
            display_value=display,
            safe_display=display if ind_type == "sha256" else defang(display),
            sha256=sha256_hex(normalized),
            origin=origin,
            first_seen_in=location,
            occurrences=[location],
            scope=scope,
            is_public=is_public,
            external_lookup_allowed=external_ok,
            scoring_eligible=scoring_eligible,
            allowlisted=allowlisted,
            extraction_warning=warning,
        )
        self._items[key] = indicator
        return indicator

    def add_url(
        self, value: str, *, origin: str, location: str, scoring_eligible: bool = True
    ) -> tuple[Indicator | None, UrlParts | None]:
        try:
            parts = canonical_url(value)
        except IndicatorError as exc:
            self.warnings.append(f"indicator_rejected:url:{location}:{exc}")
            return None, None
        indicator = self.add(
            "url", value, origin=origin, location=location, scoring_eligible=scoring_eligible
        )
        self.add(
            parts.host_type,
            parts.host,
            origin=origin,
            location=f"{location}#host",
            scoring_eligible=scoring_eligible,
        )
        return indicator, parts

    def results(self) -> list[Indicator]:
        return list(self._items.values())

    # -- internals -------------------------------------------------------------------------

    def _canonicalize(self, ind_type: str, value: str) -> tuple[str, str, str | None]:
        if ind_type == "url":
            parts = canonical_url(value)
            warning = ",".join(parts.warnings) or None
            return parts.normalized, value.strip(), warning
        if ind_type == "domain":
            domain = canonical_domain(value)
            return domain, domain_display(domain), None
        if ind_type == "ip":
            ip = canonical_ip(value)
            return ip, ip, None
        if ind_type == "email":
            address = canonical_email(value)
            local, _, domain = address.rpartition("@")
            return address, f"{local}@{domain_display(domain)}", None
        if ind_type == "sha256":
            digest = canonical_sha256(value)
            return digest, digest, None
        raise IndicatorError(f"unsupported indicator type {ind_type!r}")

    def _domain_scope(self, domain: str) -> tuple[str, bool, bool, bool]:
        allowlisted = domain_matches(domain, self.policy.allowlist_domains)
        if domain_matches(domain, self.policy.internal_domains):
            return "internal", False, False, allowlisted
        if "." not in domain:
            return "single_label", False, False, allowlisted
        return "public", True, True, allowlisted

    def _ip_scope(self, ip: str) -> tuple[str, bool, bool, bool]:
        scope = ip_scope(ip)
        routable = scope == "public" or (
            scope == "documentation" and self.lab_doc_ranges_routable
        )
        allowlisted = ip_in_networks(ip, self.policy.allowlist_networks)
        return scope, routable, routable, allowlisted

    def _classify(self, ind_type: str, normalized: str) -> tuple[str, bool | None, bool, bool]:
        if ind_type == "domain":
            return self._domain_scope(normalized)
        if ind_type == "ip":
            return self._ip_scope(normalized)
        if ind_type == "url":
            parts = canonical_url(normalized)
            if parts.host_type == "ip":
                return self._ip_scope(parts.host)
            return self._domain_scope(parts.host)
        if ind_type == "email":
            return self._domain_scope(normalized.rpartition("@")[2])
        return "file_hash", None, True, False
