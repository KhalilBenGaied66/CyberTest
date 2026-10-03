"""SQLite state: deduplication, case status, cache, circuit breakers, VT budget,
pending approvals, and containment actions with expiries.

Every mutating operation runs in its own ``BEGIN IMMEDIATE`` transaction so
concurrent Shuffle executions cannot double-claim a dedupe key, double-decide
an approval or create two active blocks for the same target.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import check_transition
from .util import iso, parse_timestamp

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dedupe (
    dedupe_key TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    dedupe_key TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
    provider TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    result_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (provider, ioc_type, value)
);
CREATE TABLE IF NOT EXISTS provider_failures (
    provider TEXT NOT NULL,
    failed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_circuit (
    provider TEXT PRIMARY KEY,
    open_until TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vt_calls (
    called_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    case_id TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    decision_json TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    rollback_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT NOT NULL,
    adapter TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    removed_at TEXT,
    removal_reason TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_action
    ON actions (type, target, scope) WHERE status = 'active';
"""


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._read() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- deduplication ----------------------------------------------------------------------

    def claim_dedupe(
        self, key: str, case_id: str, now: datetime, window_seconds: int
    ) -> tuple[bool, str, int]:
        """Return (is_new, case_id_to_use, occurrence_count)."""
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM dedupe WHERE dedupe_key = ?", (key,)).fetchone()
            if row is not None:
                first_seen = parse_timestamp(row["first_seen_at"])
                if first_seen and now - first_seen < timedelta(seconds=window_seconds):
                    conn.execute(
                        "UPDATE dedupe SET count = count + 1, last_seen_at = ? WHERE dedupe_key = ?",
                        (iso(now), key),
                    )
                    return False, row["case_id"], row["count"] + 1
            conn.execute(
                "INSERT OR REPLACE INTO dedupe VALUES (?, ?, ?, ?, 1)",
                (key, case_id, iso(now), iso(now)),
            )
            return True, case_id, 1

    # -- cases ------------------------------------------------------------------------------

    def create_case(self, case_id: str, source_type: str, dedupe_key: str, now: datetime) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO cases VALUES (?, ?, ?, 'received', ?, ?)",
                (case_id, source_type, dedupe_key, iso(now), iso(now)),
            )

    def case_status(self, case_id: str) -> str | None:
        with self._read() as conn:
            row = conn.execute("SELECT status FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return row["status"] if row else None

    def transition(self, case_id: str, new_status: str, now: datetime) -> str:
        """Atomically move a case to ``new_status``; returns the previous status."""
        with self.tx() as conn:
            row = conn.execute("SELECT status FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown case {case_id}")
            check_transition(row["status"], new_status)
            conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (new_status, iso(now), case_id),
            )
            return row["status"]

    # -- enrichment cache -------------------------------------------------------------------

    def cache_get(self, provider: str, ioc_type: str, value: str, now: datetime) -> dict | None:
        with self._read() as conn:
            row = conn.execute(
                "SELECT result_json, expires_at FROM cache WHERE provider=? AND ioc_type=? AND value=?",
                (provider, ioc_type, value),
            ).fetchone()
        if row is None:
            return None
        expires = parse_timestamp(row["expires_at"])
        if expires is None or expires <= now:
            return None
        return json.loads(row["result_json"])

    def cache_put(
        self, provider: str, ioc_type: str, value: str, result: dict, now: datetime, ttl: int
    ) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?, ?, ?)",
                (provider, ioc_type, value, json.dumps(result, sort_keys=True), iso(now),
                 iso(now + timedelta(seconds=ttl))),
            )

    # -- circuit breaker --------------------------------------------------------------------

    def circuit_open_until(self, provider: str, now: datetime) -> datetime | None:
        with self._read() as conn:
            row = conn.execute(
                "SELECT open_until FROM provider_circuit WHERE provider = ?", (provider,)
            ).fetchone()
        if row is None:
            return None
        until = parse_timestamp(row["open_until"])
        return until if until and until > now else None

    def open_circuit(self, provider: str, until: datetime, reason: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO provider_circuit VALUES (?, ?, ?)",
                (provider, iso(until), reason),
            )

    def record_failure(
        self, provider: str, now: datetime, *, threshold: int, window: int, open_seconds: int
    ) -> bool:
        """Record a provider failure; returns True when the circuit was opened."""
        cutoff = iso(now - timedelta(seconds=window))
        with self.tx() as conn:
            conn.execute("DELETE FROM provider_failures WHERE failed_at < ?", (cutoff,))
            conn.execute("INSERT INTO provider_failures VALUES (?, ?)", (provider, iso(now)))
            count = conn.execute(
                "SELECT COUNT(*) FROM provider_failures WHERE provider = ?", (provider,)
            ).fetchone()[0]
            if count >= threshold:
                conn.execute(
                    "INSERT OR REPLACE INTO provider_circuit VALUES (?, ?, ?)",
                    (provider, iso(now + timedelta(seconds=open_seconds)), "failure_threshold"),
                )
                return True
        return False

    def record_success(self, provider: str) -> None:
        with self.tx() as conn:
            conn.execute("DELETE FROM provider_failures WHERE provider = ?", (provider,))

    # -- VirusTotal budget ------------------------------------------------------------------

    def try_consume_vt(self, now: datetime, per_minute: int, per_day: int) -> bool:
        with self.tx() as conn:
            conn.execute("DELETE FROM vt_calls WHERE called_at < ?", (iso(now - timedelta(days=1)),))
            minute = conn.execute(
                "SELECT COUNT(*) FROM vt_calls WHERE called_at >= ?",
                (iso(now - timedelta(minutes=1)),),
            ).fetchone()[0]
            day = conn.execute("SELECT COUNT(*) FROM vt_calls").fetchone()[0]
            if minute >= per_minute or day >= per_day:
                return False
            conn.execute("INSERT INTO vt_calls VALUES (?)", (iso(now),))
            return True

    # -- approvals --------------------------------------------------------------------------

    def create_approval(
        self, case_id: str, token_sha256: str, action_hash: str, now: datetime, expires: datetime
    ) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, 'pending', ?, ?, NULL, NULL)",
                (case_id, token_sha256, action_hash, iso(now), iso(expires)),
            )

    def get_approval(self, case_id: str) -> dict[str, Any] | None:
        with self._read() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["decision"] = json.loads(record.pop("decision_json") or "null")
        return record

    def finish_approval(
        self, case_id: str, status: str, decision: dict[str, Any] | None, now: datetime
    ) -> bool:
        """Move a pending approval to a final status. False if it was no longer pending."""
        with self.tx() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, decision_json = ? "
                "WHERE case_id = ? AND status = 'pending'",
                (status, iso(now), json.dumps(decision, sort_keys=True) if decision else None, case_id),
            )
            return cursor.rowcount == 1

    def overdue_approvals(self, now: datetime) -> list[str]:
        with self._read() as conn:
            rows = conn.execute(
                "SELECT case_id FROM approvals WHERE status = 'pending' AND expires_at <= ?",
                (iso(now),),
            ).fetchall()
        return [row["case_id"] for row in rows]

    # -- containment actions ----------------------------------------------------------------

    def insert_action(self, record: dict[str, Any]) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO actions (action_id, rollback_id, case_id, type, target, scope, adapter, "
                "mode, status, created_at, expires_at) VALUES "
                "(:action_id, :rollback_id, :case_id, :type, :target, :scope, :adapter, :mode, "
                "'active', :created_at, :expires_at)",
                record,
            )

    def active_action(self, action_type: str, target: str, scope: str) -> dict[str, Any] | None:
        with self._read() as conn:
            row = conn.execute(
                "SELECT * FROM actions WHERE type=? AND target=? AND scope=? AND status='active'",
                (action_type, target, scope),
            ).fetchone()
        return dict(row) if row else None

    def get_action(self, action_or_rollback_id: str) -> dict[str, Any] | None:
        with self._read() as conn:
            row = conn.execute(
                "SELECT * FROM actions WHERE action_id = ? OR rollback_id = ?",
                (action_or_rollback_id, action_or_rollback_id),
            ).fetchone()
        return dict(row) if row else None

    def finish_action(self, action_id: str, status: str, reason: str, now: datetime) -> bool:
        with self.tx() as conn:
            cursor = conn.execute(
                "UPDATE actions SET status = ?, removed_at = ?, removal_reason = ? "
                "WHERE action_id = ? AND status = 'active'",
                (status, iso(now), reason, action_id),
            )
            return cursor.rowcount == 1

    def expired_actions(self, now: datetime) -> list[dict[str, Any]]:
        with self._read() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE status = 'active' AND expires_at <= ? ORDER BY expires_at",
                (iso(now),),
            ).fetchall()
        return [dict(row) for row in rows]

    def actions_for_case(self, case_id: str) -> list[dict[str, Any]]:
        with self._read() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE case_id = ? ORDER BY created_at", (case_id,)
            ).fetchall()
        return [dict(row) for row in rows]
