"""Append-only, hash-chained JSONL audit ledger.

Every state transition writes one event to ``audit/events-YYYY-MM.jsonl`` and a
copy to ``cases/<case_id>/events.jsonl``. Each event stores the hash of the
previous ledger event, so editing, reordering or deleting a line breaks the
chain. This is tamper-*evident*, not immutable storage: production would ship
events to access-controlled, WORM-capable central storage.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .util import canonical_json, iso, parse_timestamp, sha256_hex, utcnow

AUDIT_SCHEMA_VERSION = "1.0"
EVENT_TYPES = frozenset(
    {
        "received",
        "normalized",
        "enriched",
        "scored",
        "approval_requested",
        "decision",
        "action",
        "rollback",
        "notification",
        "closed",
        "error",
        "duplicate_suppressed",
    }
)
REDACTED_KEYS = frozenset(
    {
        "token",
        "approval_token",
        "callback_token",
        "secret",
        "api_key",
        "apikey",
        "auth_key",
        "authorization",
        "password",
        "eml_base64",
        "raw_bytes",
        "body",
        "attachment_bytes",
    }
)
REDACTED = "[REDACTED]"


class AuditWriteError(RuntimeError):
    """The ledger could not durably record an event. Never report success after this."""


def redact(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            k: (REDACTED if k.lower() in REDACTED_KEYS else redact(v, secrets)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret and secret in value:
                value = value.replace(secret, REDACTED)
        return value
    return value


def event_hash(event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "event_hash"}
    return "sha256:" + sha256_hex(canonical_json(body))


def _last_line(path: Path) -> str | None:
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        chunk = 4096
        data = b""
        position = end
        while position > 0:
            step = min(chunk, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
            stripped = data.rstrip(b"\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1].decode("utf-8")
            chunk *= 2
        stripped = data.rstrip(b"\n")
        return stripped.decode("utf-8") if stripped else None


class AuditLedger:
    def __init__(
        self,
        audit_dir: Path,
        cases_dir: Path,
        *,
        secrets: tuple[str, ...] = (),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.audit_dir = Path(audit_dir)
        self.cases_dir = Path(cases_dir)
        self.secrets = secrets
        self.clock = clock
        self._lock = threading.Lock()
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._lock, open(self.audit_dir / ".ledger.lock", "a") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def ledger_files(self) -> list[Path]:
        return sorted(self.audit_dir.glob("events-*.jsonl"))

    def _previous_hash(self) -> str | None:
        for path in reversed(self.ledger_files()):
            line = _last_line(path)
            if line:
                return json.loads(line)["event_hash"]
        return None

    def case_events_path(self, case_id: str) -> Path:
        return self.cases_dir / case_id / "events.jsonl"

    def case_events(self, case_id: str) -> list[dict[str, Any]]:
        path = self.case_events_path(case_id)
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def append(
        self,
        case_id: str,
        event_type: str,
        *,
        actor: dict[str, str] | None = None,
        source: dict[str, Any] | None = None,
        status: str | None = None,
        input_artifact_hashes: list[dict[str, str]] | None = None,
        score: dict[str, Any] | None = None,
        decision: dict[str, Any] | None = None,
        action: dict[str, Any] | None = None,
        enrichment_health: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown audit event type {event_type!r}")
        try:
            with self._exclusive():
                now = self.clock()
                ledger_path = self.audit_dir / f"events-{now:%Y-%m}.jsonl"
                existing = self.ledger_files()
                if existing and existing[-1].name > ledger_path.name:
                    ledger_path = existing[-1]  # never write behind the chain head
                case_path = self.case_events_path(case_id)
                sequence = 1
                if case_path.exists():
                    last = _last_line(case_path)
                    sequence = (json.loads(last)["sequence"] + 1) if last else 1
                event: dict[str, Any] = {
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "event_id": str(uuid.uuid4()),
                    "case_id": case_id,
                    "sequence": sequence,
                    "event_type": event_type,
                    "occurred_at": iso(now),
                    "actor": actor or {"type": "system", "id": "phishing-soar", "display": "Phishing SOAR"},
                    "source": source or {},
                    "status": status,
                    "input_artifact_hashes": input_artifact_hashes or [],
                    "score": score,
                    "decision": decision,
                    "action": action,
                    "enrichment_health": enrichment_health or {},
                    "details": details or {},
                }
                event = redact(event, self.secrets)
                event["prev_event_hash"] = self._previous_hash()
                event["event_hash"] = event_hash(event)
                line = json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
                for path in (ledger_path, case_path):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with open(path, "a", encoding="utf-8") as handle:
                        handle.write(line)
                        handle.flush()
                        os.fsync(handle.fileno())
                return event
        except AuditWriteError:
            raise
        except (OSError, ValueError, KeyError) as exc:
            raise AuditWriteError(f"audit write failed: {exc}") from exc


def verify_chain(audit_dir: Path) -> dict[str, Any]:
    """Recompute every event hash and link. Returns a report; ``ok`` is False on any break."""
    errors: list[dict[str, Any]] = []
    previous: str | None = None
    previous_time = None
    sequences: dict[str, int] = {}
    count = 0
    files = sorted(Path(audit_dir).glob("events-*.jsonl"))
    for path in files:
        with open(path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                count += 1
                where = {"file": path.name, "line": number}
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    errors.append({**where, "error": "invalid_json"})
                    previous = None
                    continue
                if event.get("event_hash") != event_hash(event):
                    errors.append({**where, "error": "event_hash_mismatch", "event_id": event.get("event_id")})
                if event.get("prev_event_hash") != previous:
                    errors.append({**where, "error": "broken_link", "event_id": event.get("event_id")})
                case_id = event.get("case_id")
                expected = sequences.get(case_id, 0) + 1
                if event.get("sequence") != expected:
                    errors.append({**where, "error": "sequence_gap", "case_id": case_id,
                                   "expected": expected, "found": event.get("sequence")})
                sequences[case_id] = event.get("sequence") or expected
                occurred = parse_timestamp(event.get("occurred_at"))
                if previous_time and occurred and occurred < previous_time:
                    errors.append({**where, "error": "time_went_backwards"})
                previous_time = occurred or previous_time
                previous = event.get("event_hash")
    return {
        "ok": not errors,
        "events": count,
        "files": [p.name for p in files],
        "cases": len(sequences),
        "head": previous,
        "errors": errors,
    }
