"""Human approval gate.

The callback token is random, single-use, stored only as a SHA-256 hash, bound
to one case and to the hash of the exact proposed actions, and expires after
the approval timeout (30 minutes by default). Validation happens before any
state changes, a second decision is idempotent, and a timeout never contains.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .state import StateStore
from .util import canonical_json, iso, parse_timestamp, sha256_hex

APPROVE_VERDICTS = frozenset({"malicious"})
REJECT_VERDICTS = frozenset({"benign", "suspicious_no_action"})
MIN_REASON_LENGTH = 10


class ApprovalError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def action_hash(actions: list[dict[str, Any]]) -> str:
    return "sha256:" + sha256_hex(canonical_json(actions))


@dataclass(frozen=True)
class DecisionOutcome:
    result: str  # recorded | already_recorded | expired
    decision: dict[str, Any] | None
    approval_status: str


class ApprovalGate:
    def __init__(self, state: StateStore, timeout_seconds: int) -> None:
        self.state = state
        self.timeout_seconds = timeout_seconds

    def open(self, case_id: str, proposed: list[dict[str, Any]], now: datetime) -> tuple[str, dict[str, Any]]:
        token = secrets.token_urlsafe(32)
        expires = now + timedelta(seconds=self.timeout_seconds)
        bound_hash = action_hash(proposed)
        self.state.create_approval(case_id, sha256_hex(token), bound_hash, now, expires)
        return token, {"status": "pending", "proposed_action_hash": bound_hash,
                       "created_at": iso(now), "expires_at": iso(expires)}

    def decide(
        self,
        case_id: str,
        token: str,
        payload: dict[str, Any],
        proposed: list[dict[str, Any]],
        now: datetime,
    ) -> DecisionOutcome:
        record = self.state.get_approval(case_id)
        if record is None:
            raise ApprovalError("no_pending_approval")
        if not token or not hmac.compare_digest(sha256_hex(token), record["token_sha256"]):
            raise ApprovalError("invalid_callback_token")
        if record["status"] != "pending":
            return DecisionOutcome("already_recorded", record["decision"], record["status"])
        expires = parse_timestamp(record["expires_at"])
        if expires is not None and now >= expires:
            return DecisionOutcome("expired", None, "pending")
        current_hash = action_hash(proposed)
        if not hmac.compare_digest(current_hash, record["action_hash"]):
            raise ApprovalError("proposal_changed", "proposed actions no longer match the approval request")
        supplied_hash = payload.get("proposed_action_hash")
        if supplied_hash and not hmac.compare_digest(str(supplied_hash), record["action_hash"]):
            raise ApprovalError("action_hash_mismatch")

        decision_kind = str(payload.get("decision", "")).strip().lower()
        verdict = str(payload.get("verdict", "")).strip().lower()
        reason = " ".join(str(payload.get("reason", "")).split())
        analyst = str(payload.get("analyst", "")).strip()
        if not analyst:
            raise ApprovalError("missing_analyst")
        if len(reason) < MIN_REASON_LENGTH:
            raise ApprovalError("missing_reason", f"reason must be at least {MIN_REASON_LENGTH} characters")
        requested = payload.get("approved_actions") or []
        if not isinstance(requested, list) or not all(isinstance(a, str) for a in requested):
            raise ApprovalError("invalid_actions")
        proposed_ids = {a["action_id"] for a in proposed}

        if decision_kind == "approve":
            if verdict not in APPROVE_VERDICTS:
                raise ApprovalError("invalid_verdict", "approval requires verdict=malicious")
            unknown = sorted(set(requested) - proposed_ids)
            if unknown:
                raise ApprovalError("invalid_action", f"not proposed for this case: {unknown}")
        elif decision_kind == "reject":
            if verdict not in REJECT_VERDICTS:
                raise ApprovalError("invalid_verdict", "rejection requires verdict=benign|suspicious_no_action")
            if requested:
                raise ApprovalError("invalid_action", "a rejection cannot approve actions")
        else:
            raise ApprovalError("invalid_decision", "decision must be approve or reject")

        active_seconds = payload.get("analyst_active_seconds")
        decision = {
            "approval": "approved" if decision_kind == "approve" else "rejected",
            "verdict": verdict,
            "reason": reason[:2000],
            "analyst": analyst[:128],
            "approved_actions": sorted(set(requested)),
            "proposed_action_hash": record["action_hash"],
            "decided_at": iso(now),
            "analyst_active_seconds": float(active_seconds) if isinstance(active_seconds, (int, float)) else None,
        }
        status = decision["approval"]
        if not self.state.finish_approval(case_id, status, decision, now):
            latest = self.state.get_approval(case_id) or {}
            return DecisionOutcome("already_recorded", latest.get("decision"), latest.get("status", "unknown"))
        return DecisionOutcome("recorded", decision, status)

    def expire(self, case_id: str, now: datetime) -> bool:
        """Mark a pending approval timed out. Returns False if it was already decided."""
        return self.state.finish_approval(
            case_id, "timed_out", {"approval": "timeout", "decided_at": iso(now)}, now
        )
