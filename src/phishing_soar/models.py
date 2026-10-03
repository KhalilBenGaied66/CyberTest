"""Data contracts shared by both intake sources (see ``schemas/``)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"

INDICATOR_TYPES = ("url", "domain", "ip", "email", "sha256")

# Canonical case lifecycle. Transitions are monotonic; ``failed_needs_review``
# is reachable from any non-terminal state when an internal error occurs.
CASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "received": frozenset({"normalized", "parse_partial"}),
    "normalized": frozenset({"enriched", "enriched_degraded"}),
    "parse_partial": frozenset({"enriched", "enriched_degraded"}),
    "enriched": frozenset({"scored"}),
    "enriched_degraded": frozenset({"scored"}),
    "scored": frozenset({"awaiting_approval"}),
    "awaiting_approval": frozenset({"approved", "rejected", "approval_timeout"}),
    "approved": frozenset(
        {"responded", "response_partial", "response_failed_needs_review", "needs_review"}
    ),
    "rejected": frozenset({"closed"}),
    "approval_timeout": frozenset({"needs_review"}),
    "responded": frozenset({"audited"}),
    "response_partial": frozenset({"audited"}),
    "response_failed_needs_review": frozenset({"audited"}),
    "needs_review": frozenset({"audited"}),
    "closed": frozenset({"audited"}),
    "failed_needs_review": frozenset(),
    "audited": frozenset(),
}
TERMINAL_STATUSES = frozenset({"audited", "failed_needs_review"})


class InvalidTransition(RuntimeError):
    pass


def check_transition(current: str, new: str) -> None:
    if new == "failed_needs_review" and current not in TERMINAL_STATUSES:
        return
    allowed = CASE_TRANSITIONS.get(current)
    if allowed is None or new not in allowed:
        raise InvalidTransition(f"illegal case transition {current} -> {new}")


@dataclass
class Indicator:
    indicator_id: str
    type: str
    value: str
    normalized_value: str
    display_value: str
    safe_display: str
    sha256: str
    origin: str
    first_seen_in: str
    occurrences: list[str] = field(default_factory=list)
    scope: str = "public"
    is_public: bool | None = True
    external_lookup_allowed: bool = True
    scoring_eligible: bool = True
    allowlisted: bool = False
    extraction_warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Indicator:
        return cls(**data)


@dataclass
class NormalizedCase:
    case_id: str
    source_type: str
    source_event_id: str
    received_at: str
    observed_at: str | None
    status: str
    entities: dict[str, Any]
    indicators: list[Indicator]
    evidence: dict[str, Any]
    parse_warnings: list[str]
    dedupe_key: str
    raw_ref: dict[str, Any]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["indicators"] = [i.to_dict() for i in self.indicators]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NormalizedCase:
        values = dict(data)
        values["indicators"] = [Indicator.from_dict(i) for i in data.get("indicators", [])]
        return cls(**values)


@dataclass
class EnrichmentResult:
    """One answer per (indicator, provider).

    ``status`` is ``ok`` when the provider answered (``match`` is then True or
    False), ``unknown`` when it could not answer (``match`` is None), and
    ``not_applicable``/``skipped`` when no lookup should happen. ``unknown`` is
    never equivalent to a clean result.
    """

    provider: str
    indicator_id: str
    indicator_type: str
    indicator_value: str
    status: str
    match: bool | None
    verdict: str | None
    confidence: int | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    fetched_at: str | None = None
    expires_at: str | None = None
    raw_ref: str | None = None
    from_cache: bool = False
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnrichmentResult:
        return cls(**data)
