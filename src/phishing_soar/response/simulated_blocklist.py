"""Simulated lab blocklist (the default ``RESPONSE_MODE=simulate`` adapter).

Writes an append-only operation log (``temporary_blocks.jsonl``) and keeps the
effective state in SQLite. Nothing changes real traffic. Add and remove are
idempotent, re-validate the target, cap the TTL at 60 minutes, and verify the
resulting state before returning a receipt.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..config import Policy
from ..state import StateStore
from ..util import append_jsonl, iso, utcnow
from .safety import BLOCK_TYPES, UnsafeTargetError, check_block_target, check_ttl


class ResponseError(RuntimeError):
    """The adapter could not apply or remove an action."""


class SimulatedBlocklist:
    adapter = "simulated_blocklist"
    mode = "simulate"

    def __init__(
        self,
        oplog_path: Path,
        state: StateStore,
        policy: Policy,
        *,
        lab_doc_ranges_routable: bool,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.oplog_path = Path(oplog_path)
        self.state = state
        self.policy = policy
        self.lab_doc_ranges_routable = lab_doc_ranges_routable
        self.clock = clock
        # Fault injection for failure-path tests and demos.
        self.fail_add = False
        self.fail_remove = False

    def _receipt(self, record: dict[str, Any], result: str, verified: bool, **extra: Any) -> dict[str, Any]:
        return {
            "action_id": record["action_id"],
            "rollback_id": record["rollback_id"],
            "type": record["type"],
            "target": record["target"],
            "scope": record["scope"],
            "adapter": self.adapter,
            "mode": self.mode,
            "result": result,
            "verified": verified,
            "created_at": record.get("created_at"),
            "expires_at": record.get("expires_at"),
            **extra,
        }

    def add(self, case_id: str, action: dict[str, Any]) -> dict[str, Any]:
        if action.get("type") not in BLOCK_TYPES:
            raise UnsafeTargetError("unsupported_action_type")
        target = check_block_target(
            BLOCK_TYPES[action["type"]], action["target"], self.policy,
            lab_doc_ranges_routable=self.lab_doc_ranges_routable,
        )
        ttl = check_ttl(action["ttl_seconds"])
        scope = str(action["scope"])
        existing = self.state.active_action(action["type"], target, scope)
        if existing is not None:
            return self._receipt(existing, "already_active", True, linked_action_id=existing["action_id"],
                                 ttl_seconds=ttl, case_id=case_id)
        if self.fail_add:
            raise ResponseError("simulated add failure")
        now = self.clock()
        record = {
            "action_id": action["action_id"],
            "rollback_id": "rb-" + uuid.uuid4().hex[:12],
            "case_id": case_id,
            "type": action["type"],
            "target": target,
            "scope": scope,
            "adapter": self.adapter,
            "mode": self.mode,
            "created_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=ttl)),
        }
        try:
            self.state.insert_action(record)
        except sqlite3.IntegrityError:
            existing = self.state.active_action(action["type"], target, scope)
            if existing is None:
                raise ResponseError("action insert conflicted and no active block exists") from None
            return self._receipt(existing, "already_active", True, linked_action_id=existing["action_id"],
                                 ttl_seconds=ttl, case_id=case_id)
        append_jsonl(self.oplog_path, {"op": "add", "at": iso(now), **record, "ttl_seconds": ttl})
        current = self.state.active_action(action["type"], target, scope)
        verified = current is not None and current["action_id"] == record["action_id"]
        return self._receipt(record, "success" if verified else "unverified", verified,
                             ttl_seconds=ttl, case_id=case_id)

    def remove(self, action_or_rollback_id: str, *, reason: str) -> dict[str, Any]:
        record = self.state.get_action(action_or_rollback_id)
        if record is None:
            raise ResponseError(f"unknown action {action_or_rollback_id}")
        if record["status"] != "active":
            return self._receipt(record, "already_removed", True, removed_at=record["removed_at"],
                                 removal_reason=record["removal_reason"])
        if self.fail_remove:
            raise ResponseError("simulated remove failure")
        now = self.clock()
        self.state.finish_action(record["action_id"], "removed", reason, now)
        append_jsonl(self.oplog_path, {"op": "remove", "at": iso(now), "action_id": record["action_id"],
                                       "rollback_id": record["rollback_id"], "target": record["target"],
                                       "scope": record["scope"], "reason": reason})
        still_active = self.state.active_action(record["type"], record["target"], record["scope"])
        verified = still_active is None or still_active["action_id"] != record["action_id"]
        return self._receipt(record, "success" if verified else "unverified", verified,
                             removed_at=iso(now), removal_reason=reason)
