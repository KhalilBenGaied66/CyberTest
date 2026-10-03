"""Containment target safety checks, shared by proposal (scoring) and execution."""

from __future__ import annotations

from ..canonical import (
    IndicatorError,
    canonical_domain,
    canonical_ip,
    domain_matches,
    ip_in_networks,
    ip_scope,
)
from ..config import MAX_BLOCK_TTL_SECONDS, Policy

BLOCK_TYPES = {"temporary_ip_block": "ip", "temporary_domain_block": "domain"}


class UnsafeTargetError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def check_block_target(
    target_type: str, target: str, policy: Policy, *, lab_doc_ranges_routable: bool
) -> str:
    """Return the canonical target or raise :class:`UnsafeTargetError`.

    Refuses private/loopback/reserved IPs, management and allowlisted networks,
    internal/allowlisted/protected domains and shared URL-shortener domains.
    """
    try:
        if target_type == "ip":
            ip = canonical_ip(target)
            scope = ip_scope(ip)
            if not (scope == "public" or (scope == "documentation" and lab_doc_ranges_routable)):
                raise UnsafeTargetError(f"non_public_ip:{scope}")
            if ip_in_networks(ip, policy.protected_networks):
                raise UnsafeTargetError("protected_network")
            if ip_in_networks(ip, policy.allowlist_networks):
                raise UnsafeTargetError("allowlisted")
            return ip
        if target_type == "domain":
            domain = canonical_domain(target)
            if "." not in domain:
                raise UnsafeTargetError("single_label_domain")
            if domain_matches(domain, policy.internal_domains):
                raise UnsafeTargetError("internal_domain")
            if domain_matches(domain, policy.allowlist_domains):
                raise UnsafeTargetError("allowlisted")
            if domain_matches(domain, policy.protected_domains):
                raise UnsafeTargetError("protected_domain")
            if domain in policy.url_shorteners:
                raise UnsafeTargetError("shared_infrastructure")
            return domain
    except IndicatorError as exc:
        raise UnsafeTargetError("invalid_target") from exc
    raise UnsafeTargetError("unsupported_target_type")


def check_ttl(ttl_seconds: int) -> int:
    ttl = int(ttl_seconds)
    if not 0 < ttl <= MAX_BLOCK_TTL_SECONDS:
        raise UnsafeTargetError("ttl_out_of_bounds")
    return ttl
