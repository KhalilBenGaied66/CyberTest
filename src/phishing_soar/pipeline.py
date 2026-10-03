"""Case orchestration shared by both entry workflows.

``received -> normalized|parse_partial -> enriched|enriched_degraded -> scored ->
awaiting_approval -> approved|rejected|approval_timeout ->
responded|closed|needs_review|... -> audited``

Shuffle calls these operations (through :mod:`service`) and keeps the visual
trace; the decisions themselves are deterministic, tested Python. Containment
happens only inside :meth:`SoarPipeline.decide` after a validated analyst
approval, and every step writes a hash-chained audit event.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .approval import ApprovalError, ApprovalGate
from .audit import AuditLedger, AuditWriteError
from .config import Settings
from .email_parser import normalize_email
from .enrichment import Enricher, LocalIocIndex
from .enrichment.base import Transport
from .models import NormalizedCase
from .notify import Notifier, build_notifier
from .response import ResponseError, SimulatedBlocklist, UnsafeTargetError
from .scoring import score_case
from .state import StateStore
from .tickets import TicketWriter, render_card
from .util import canonical_json, iso, parse_timestamp, sha256_hex, utcnow, write_json_atomic
from .wazuh_normalizer import (
    WazuhIntakeError,
    check_rule_allowed,
    load_wazuh_payload,
    normalize_wazuh,
    wazuh_dedupe_key,
)

_REPORTER_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
SYSTEM_ACTOR = {"type": "system", "id": "phishing-soar", "display": "Phishing SOAR"}


class IntakeError(ValueError):
    def __init__(self, code: str, detail: str = "", case_id: str | None = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.case_id = case_id


class PipelineError(RuntimeError):
    def __init__(self, case_id: str, stage: str, cause: Exception) -> None:
        super().__init__(f"case {case_id} failed during {stage}: {cause}")
        self.case_id = case_id
        self.stage = stage


def _analyst_actor(analyst: str) -> dict[str, str]:
    return {"type": "analyst", "id": analyst, "display": analyst}


class SoarPipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: Transport | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
        notifier: Notifier | None = None,
    ) -> None:
        self.settings = settings
        self.clock = clock
        self.root = Path(settings.data_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.cases_dir = self.root / "cases"
        self.state = StateStore(self.root / "state" / "soar.db")
        self.audit = AuditLedger(
            self.root / "audit", self.cases_dir, secrets=settings.secret_values(), clock=clock
        )
        self.local_iocs = LocalIocIndex(settings.ioc_paths)
        self.enricher = Enricher(
            settings, self.state, self.local_iocs, transport=transport, clock=clock, sleep=sleep,
            raw_dir=self.root / "provider_responses",
        )
        self.approvals = ApprovalGate(self.state, settings.approval_timeout_seconds)
        self.responder = SimulatedBlocklist(
            self.root / "blocklist" / "temporary_blocks.jsonl", self.state, settings.policy,
            lab_doc_ranges_routable=settings.lab_doc_ranges_routable, clock=clock,
        )
        self.notifier = notifier or build_notifier(settings, self.root / "notifications" / "outbox.jsonl", clock)
        self.tickets = TicketWriter(self.root / "tickets")
        self._lock = threading.RLock()

    # -- snapshot helpers ---------------------------------------------------------------------

    def snapshot_path(self, case_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f-]{36}", case_id):
            raise KeyError(case_id)
        return self.cases_dir / case_id / "case.json"

    def load_case(self, case_id: str) -> dict[str, Any]:
        path = self.snapshot_path(case_id)
        if not path.exists():
            raise KeyError(case_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def _save(self, snapshot: dict[str, Any]) -> None:
        write_json_atomic(self.snapshot_path(snapshot["case_id"]), snapshot)

    def _set_status(self, snapshot: dict[str, Any], status: str) -> None:
        now = self.clock()
        self.state.transition(snapshot["case_id"], status, now)
        snapshot["status"] = status
        snapshot["status_history"].append({"status": status, "at": iso(now)})

    def _audit(self, snapshot: dict[str, Any], event_type: str, **kwargs: Any) -> dict[str, Any]:
        return self.audit.append(
            snapshot["case_id"], event_type, source=snapshot["source"], status=snapshot["status"], **kwargs
        )

    def _store_raw(self, case_id: str, data: bytes, suffix: str, kind: str) -> dict[str, Any]:
        raw_dir = self.cases_dir / case_id / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = raw_dir / f"{uuid.uuid4().hex}{suffix}"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return {"path": str(path.relative_to(self.root)), "sha256": sha256_hex(data), "size": len(data), "kind": kind}

    def _new_snapshot(
        self, case_id: str, source: dict[str, Any], hashes: list[dict[str, str]],
        labels: dict[str, str] | None, now: datetime,
    ) -> dict[str, Any]:
        return {
            "case_id": case_id,
            "status": "received",
            "outcome": None,
            "source": source,
            "input_artifact_hashes": hashes,
            "labels": {str(k)[:32]: str(v)[:64] for k, v in (labels or {}).items()},
            "status_history": [{"status": "received", "at": iso(now)}],
            "case": None,
            "enrichment": None,
            "score": None,
            "approval": None,
            "decision": None,
            "actions": [],
            "rollbacks": [],
            "notifications": [],
            "duplicates": [],
            "ticket_path": None,
            "card": None,
            "timings": {"received_at": iso(now)},
        }

    def _reject(self, source_type: str, code: str, detail: str = "") -> IntakeError:
        case_id = str(uuid.uuid4())
        self.audit.append(case_id, "error", source={"type": source_type}, status="intake_rejected",
                          details={"code": code, "detail": detail[:300]})
        return IntakeError(code, detail, case_id)

    def _fail(self, snapshot: dict[str, Any], stage: str, exc: Exception) -> None:
        if isinstance(exc, AuditWriteError):
            return  # cannot record anything durable; the caller sees the failure
        try:
            # A failed case must never stay approvable or be picked up by the timeout sweep.
            self.state.finish_approval(snapshot["case_id"], "cancelled",
                                       {"approval": "cancelled", "reason": "internal_error"}, self.clock())
            self._audit(snapshot, "error", details={"code": "internal_error", "stage": stage,
                                                    "error_type": type(exc).__name__, "message": str(exc)[:500]})
            self._set_status(snapshot, "failed_needs_review")
            snapshot["outcome"] = "failed_needs_review"
            self._save(snapshot)
        except Exception:  # pragma: no cover - best effort while already failing
            pass

    def _notify(self, snapshot: dict[str, Any], *, kind: str, recipients: list[str], subject: str,
                text: str) -> dict[str, Any]:
        result = self.notifier.send(kind=kind, case_id=snapshot["case_id"], recipients=recipients,
                                    subject=subject, text=text)
        snapshot["notifications"].append(result)
        self._audit(snapshot, "notification", details=result)
        return result

    # -- intake -------------------------------------------------------------------------------

    def ingest_email(
        self,
        raw: bytes,
        *,
        reporter: str | None = None,
        reported_at: str | None = None,
        execution_id: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            now = self.clock()
            if not raw:
                raise self._reject("email", "empty_file")
            if len(raw) > self.settings.max_eml_bytes:
                raise self._reject("email", "too_large", f"{len(raw)} > {self.settings.max_eml_bytes} bytes")
            ingest_sha = sha256_hex(raw)
            notes = []
            if reporter and not _REPORTER_RE.match(reporter.strip()):
                notes.append("reporter_not_an_email_address")
                reporter = None
            reported = parse_timestamp(reported_at) if reported_at else None
            if reported_at and reported is None:
                notes.append("unparseable_reported_at")
            case_id = str(uuid.uuid4())
            is_new, original, count = self.state.claim_dedupe(
                ingest_sha, case_id, now, self.settings.dedupe_window_seconds
            )
            hashes = [{"algorithm": "sha256", "value": ingest_sha, "kind": "eml"}]
            source = {"type": "email", "event_id": f"sha256:{ingest_sha}", "shuffle_execution_id": execution_id}
            if not is_new:
                return self._duplicate(original, count, source, hashes, now)
            raw_ref = self._store_raw(case_id, raw, ".eml", "eml")
            snapshot = self._new_snapshot(case_id, source, hashes, labels, now)
            self.state.create_case(case_id, "email", ingest_sha, now)
            self._audit(snapshot, "received", input_artifact_hashes=hashes,
                        details={"size": len(raw), "reporter": reporter,
                                 "reported_at": iso(reported) if reported else None,
                                 "dedupe_key": ingest_sha, "notes": notes})
            return self._process(
                snapshot, hashes,
                lambda: normalize_email(
                    raw, case_id=case_id, received_at=iso(now), reporter=reporter,
                    reported_at=iso(reported) if reported else None, raw_ref=raw_ref, settings=self.settings,
                ),
            )

    def ingest_wazuh(
        self,
        payload: bytes | str | dict[str, Any],
        *,
        execution_id: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            now = self.clock()
            try:
                alert, envelope = load_wazuh_payload(payload, max_bytes=self.settings.max_wazuh_bytes)
                check_rule_allowed(alert, self.settings.policy)
            except WazuhIntakeError as exc:
                raise self._reject("wazuh", exc.code, exc.detail) from exc
            raw_bytes = payload if isinstance(payload, bytes) else (
                payload.encode("utf-8") if isinstance(payload, str) else canonical_json(payload).encode("utf-8")
            )
            dedupe_key, source_event_id, _ = wazuh_dedupe_key(alert)
            hashes = [{"algorithm": "sha256", "value": sha256_hex(raw_bytes), "kind": "wazuh_alert"}]
            source = {"type": "wazuh", "event_id": source_event_id, "shuffle_execution_id": execution_id}
            case_id = str(uuid.uuid4())
            is_new, original, count = self.state.claim_dedupe(
                dedupe_key, case_id, now, self.settings.dedupe_window_seconds
            )
            if not is_new:
                return self._duplicate(original, count, source, hashes, now)
            raw_ref = self._store_raw(case_id, raw_bytes, ".json", "wazuh_alert")
            snapshot = self._new_snapshot(case_id, source, hashes, labels, now)
            self.state.create_case(case_id, "wazuh", dedupe_key, now)
            self._audit(snapshot, "received", input_artifact_hashes=hashes,
                        details={"size": len(raw_bytes), "dedupe_key": dedupe_key,
                                 "rule_id": str(alert["rule"].get("id"))})
            return self._process(
                snapshot, hashes,
                lambda: normalize_wazuh(alert, envelope, case_id=case_id, received_at=iso(now),
                                        raw_ref=raw_ref, settings=self.settings),
            )

    def _duplicate(
        self, case_id: str, count: int, source: dict[str, Any], hashes: list[dict[str, str]], now: datetime
    ) -> dict[str, Any]:
        try:
            snapshot = self.load_case(case_id)
        except KeyError:
            snapshot = None
        status = snapshot["status"] if snapshot else self.state.case_status(case_id)
        self.audit.append(case_id, "duplicate_suppressed", source=source, status=status,
                          input_artifact_hashes=hashes, details={"occurrence": count})
        if snapshot is not None:
            snapshot["duplicates"].append({"received_at": iso(now), "ingest_sha256": hashes[0]["value"],
                                           "shuffle_execution_id": source.get("shuffle_execution_id")})
            self._save(snapshot)
            if snapshot.get("ticket_path"):
                self.tickets.write(snapshot)
        score = (snapshot or {}).get("score") or {}
        return {
            "case_id": case_id,
            "duplicate": True,
            "result": "duplicate_suppressed",
            "status": status,
            "occurrence": count,
            "score": {"total": score.get("total"), "band": score.get("band")} if score else None,
        }

    def _process(
        self, snapshot: dict[str, Any], hashes: list[dict[str, str]], normalize: Callable[[], NormalizedCase]
    ) -> dict[str, Any]:
        case_id = snapshot["case_id"]
        stage = "normalize"
        try:
            case = normalize()
            snapshot["case"] = case.to_dict()
            self._set_status(snapshot, case.status)
            self._audit(snapshot, "normalized", input_artifact_hashes=hashes,
                        details={"indicators": len(case.indicators), "dedupe_key": case.dedupe_key,
                                 "parse_warnings": case.parse_warnings[:50]})

            stage = "enrich"
            report = self.enricher.enrich(case.indicators)
            snapshot["enrichment"] = report.to_dict()
            self._set_status(snapshot, "enriched" if report.enrichment_mode == "online" else "enriched_degraded")
            self._audit(snapshot, "enriched", enrichment_health=report.health_summary(),
                        details={"results": len(report.results), "provider_reasons": report.provider_reasons,
                                 "local_load_warnings": report.local_load_warnings[:20]})

            stage = "score"
            score = score_case(case, report, self.settings)
            snapshot["score"] = score.to_dict()
            self._set_status(snapshot, "scored")
            self._audit(snapshot, "scored", score=score.summary())

            stage = "approval_request"
            token, approval = self.approvals.open(case_id, score.proposed_actions, self.clock())
            snapshot["approval"] = approval
            snapshot["ticket_path"] = str(self.tickets.path_for(case_id))
            self._set_status(snapshot, "awaiting_approval")
            snapshot["card"] = render_card(snapshot)
            self.tickets.write(snapshot)
            notification = self._notify(
                snapshot, kind="analyst_card", recipients=[self.settings.analyst_address],
                subject=f"[SOAR {score.band.upper()} {score.total}] {case.source_type} case {case_id}",
                text=snapshot["card"],
            )
            snapshot["timings"]["card_ready_at"] = iso(self.clock())
            self._audit(snapshot, "approval_requested",
                        details={"proposed_actions": [
                            {k: a[k] for k in ("action_id", "type", "target", "scope", "ttl_seconds", "mode")}
                            for a in score.proposed_actions],
                            "proposed_action_hash": approval["proposed_action_hash"],
                            "expires_at": approval["expires_at"],
                            "notification_status": notification["status"],
                            "ticket": snapshot["ticket_path"]})
            self._save(snapshot)
        except Exception as exc:
            self._fail(snapshot, stage, exc)
            if isinstance(exc, AuditWriteError):
                raise
            raise PipelineError(case_id, stage, exc) from exc
        return {
            "case_id": case_id,
            "duplicate": False,
            "result": "awaiting_approval",
            "status": snapshot["status"],
            "source_type": case.source_type,
            "score": {"total": score.total, "band": score.band, "model_version": score.model_version},
            "enrichment": {"mode": report.enrichment_mode, "completeness": report.completeness},
            "recommended_verdict": score.recommended_verdict,
            "proposed_actions": score.proposed_actions,
            "flags": score.flags,
            "approval": {"token": token, "expires_at": approval["expires_at"],
                         "proposed_action_hash": approval["proposed_action_hash"]},
            "card": snapshot["card"],
            "ticket_path": snapshot["ticket_path"],
        }

    # -- decision -----------------------------------------------------------------------------

    def decide(self, case_id: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            now = self.clock()
            snapshot = self.load_case(case_id)
            proposed = (snapshot.get("score") or {}).get("proposed_actions", [])
            try:
                outcome = self.approvals.decide(case_id, token, payload, proposed, now)
            except ApprovalError as exc:
                if exc.code == "invalid_callback_token":
                    self._audit(snapshot, "error", details={"code": "invalid_callback_token",
                                                            "claimed_analyst": str(payload.get("analyst", ""))[:128]})
                raise
            if outcome.result == "already_recorded":
                return {"case_id": case_id, "result": "decision_already_recorded", "status": snapshot["status"],
                        "decision": snapshot.get("decision") or outcome.decision}
            if outcome.result == "expired":
                self._timeout(snapshot, now)
                return {"case_id": case_id, "result": "approval_expired", "status": snapshot["status"],
                        "outcome": snapshot["outcome"]}
            decision = outcome.decision or {}
            snapshot["decision"] = decision
            snapshot["timings"]["decided_at"] = decision["decided_at"]
            try:
                self._set_status(snapshot, decision["approval"])
                self._audit(snapshot, "decision", actor=_analyst_actor(decision["analyst"]), decision=decision)
                if decision["approval"] == "rejected":
                    self._close_rejected(snapshot)
                else:
                    self._respond(snapshot, decision, proposed)
                self._save(snapshot)
            except Exception as exc:
                self._fail(snapshot, "respond", exc)  # keeps any applied receipts; expiry still removes blocks
                if isinstance(exc, AuditWriteError):
                    raise
                raise PipelineError(case_id, "respond", exc) from exc
            return {"case_id": case_id, "result": "decision_recorded", "status": snapshot["status"],
                    "outcome": snapshot["outcome"], "decision": decision, "actions": snapshot["actions"]}

    def _reporter(self, snapshot: dict[str, Any]) -> str | None:
        case = snapshot.get("case") or {}
        return (case.get("entities") or {}).get("reporter")

    def _close_rejected(self, snapshot: dict[str, Any]) -> None:
        decision = snapshot["decision"]
        reporter = self._reporter(snapshot)
        if reporter:
            self._notify(snapshot, kind="reporter_closure", recipients=[reporter],
                         subject=f"Your report {snapshot['case_id'][:8]} was reviewed",
                         text=f"An analyst reviewed your report and closed it as '{decision['verdict']}'. "
                              "No containment was applied. Thank you for reporting.")
        self._set_status(snapshot, "closed")
        snapshot["outcome"] = "closed"
        self._audit(snapshot, "closed", details={"outcome": "closed", "containment": "none",
                                                 "verdict": decision["verdict"]})
        self._set_status(snapshot, "audited")
        self.tickets.write(snapshot)

    def _apply(self, case_id: str, action: dict[str, Any]) -> dict[str, Any]:
        """Add is idempotent and re-reads current block state first, so one retry is safe."""
        try:
            return self.responder.add(case_id, action)
        except ResponseError:
            return self.responder.add(case_id, action)

    def _respond(self, snapshot: dict[str, Any], decision: dict[str, Any], proposed: list[dict[str, Any]]) -> None:
        approved = [a for a in proposed if a["action_id"] in set(decision["approved_actions"])]
        failures: list[dict[str, str]] = []
        conflicts: list[dict[str, str]] = []
        for action in approved:
            try:
                receipt = self._apply(snapshot["case_id"], action)
            except UnsafeTargetError as exc:
                conflicts.append({"action_id": action["action_id"], "reason": exc.reason})
                self._audit(snapshot, "error", details={"code": "containment_refused", "reason": exc.reason,
                                                        "action_id": action["action_id"]})
                continue
            except ResponseError as exc:
                failures.append({"action_id": action["action_id"], "error": str(exc)[:300]})
                self._audit(snapshot, "error", details={"code": "response_failed", "priority": "high",
                                                        "action_id": action["action_id"], "error": str(exc)[:300]})
                continue
            receipt["authorized_by"] = decision["analyst"]
            snapshot["actions"].append(receipt)
            self._audit(snapshot, "action", action=receipt, decision={
                "approval": decision["approval"], "analyst": decision["analyst"],
                "proposed_action_hash": decision["proposed_action_hash"]})
        suppressed = [f for f in (snapshot.get("score") or {}).get("flags", [])
                      if f == "allowlist_conflict" or f.startswith("containment_suppressed:")]
        if any(r["verified"] for r in snapshot["actions"]):
            snapshot["timings"]["response_verified_at"] = iso(self.clock())

        applied = ", ".join(f"{r['type']} {r['target'].replace('.', '[.]')} ({r['result']}, until {r['expires_at']})"
                            for r in snapshot["actions"]) or "no containment (none approved or applicable)"
        notes = [self._notify(snapshot, kind="analyst_response",
                              recipients=[self.settings.analyst_address],
                              subject=f"[SOAR] case {snapshot['case_id']} response: {len(snapshot['actions'])} action(s)",
                              text=f"Verdict {decision['verdict']} approved by {decision['analyst']}. Actions: {applied}. "
                                   f"Failures: {failures or 'none'}. Refused: {conflicts or 'none'}.")]
        reporter = self._reporter(snapshot)
        if reporter:
            notes.append(self._notify(snapshot, kind="reporter_closure", recipients=[reporter],
                                      subject=f"Your report {snapshot['case_id'][:8]} was confirmed",
                                      text="An analyst confirmed the message you reported as malicious and "
                                           "took action. Please delete it and do not interact with it."))
        if failures:
            self._notify(snapshot, kind="response_failure", recipients=[self.settings.analyst_address],
                         subject=f"[SOAR HIGH] response failed for case {snapshot['case_id']}",
                         text=f"Containment failed and needs manual review: {failures}")
            status = "response_failed_needs_review"
        elif conflicts or suppressed:
            status = "needs_review"  # allowlist/protected-target conflict: never silently "responded"
        elif any(n["status"] != "sent" for n in notes):
            status = "response_partial"
        else:
            status = "responded"
        self._set_status(snapshot, status)
        snapshot["outcome"] = status
        self._audit(snapshot, "closed", details={"outcome": status,
                                                 "actions": [r["action_id"] for r in snapshot["actions"]],
                                                 "failures": failures, "refused": conflicts,
                                                 "suppressed_at_proposal": suppressed})
        self._set_status(snapshot, "audited")
        self.tickets.write(snapshot)

    # -- scheduled jobs -----------------------------------------------------------------------

    def _timeout(self, snapshot: dict[str, Any], now: datetime) -> bool:
        if not self.approvals.expire(snapshot["case_id"], now):
            return False
        if snapshot["status"] != "awaiting_approval":
            return False  # approval closed; nothing to contain or escalate
        decision = {"approval": "timeout", "verdict": None, "analyst": "system",
                    "reason": "no analyst decision within the approval timeout", "decided_at": iso(now),
                    "approved_actions": []}
        snapshot["decision"] = decision
        self._set_status(snapshot, "approval_timeout")
        self._audit(snapshot, "decision", decision=decision)
        self._notify(snapshot, kind="escalation", recipients=[self.settings.analyst_address],
                     subject=f"[SOAR ESCALATION] approval timed out for case {snapshot['case_id']}",
                     text="No decision was recorded in time. No containment was applied; the case needs review.")
        self._set_status(snapshot, "needs_review")
        snapshot["outcome"] = "needs_review"
        self._audit(snapshot, "closed", details={"outcome": "needs_review", "containment": "none",
                                                 "reason": "approval_timeout"})
        self._set_status(snapshot, "audited")
        self.tickets.write(snapshot)
        self._save(snapshot)
        return True

    def sweep_timeouts(self) -> list[dict[str, Any]]:
        with self._lock:
            now = self.clock()
            handled = []
            for case_id in self.state.overdue_approvals(now):
                try:
                    snapshot = self.load_case(case_id)
                    if self._timeout(snapshot, now):
                        handled.append({"case_id": case_id, "result": "approval_timeout", "status": snapshot["status"]})
                except AuditWriteError:
                    raise
                except Exception as exc:  # one broken case must not stop the sweep
                    handled.append({"case_id": case_id, "result": "error", "error": type(exc).__name__})
            return handled

    def _record_rollback(self, snapshot: dict[str, Any], receipt: dict[str, Any], actor: dict[str, str]) -> None:
        snapshot["rollbacks"].append(receipt)
        for action in snapshot["actions"]:
            if action["action_id"] == receipt["action_id"]:
                action["removed_at"] = receipt.get("removed_at")
        self._audit(snapshot, "rollback", actor=actor, action=receipt)
        if snapshot.get("ticket_path"):
            self.tickets.write(snapshot)
        self._save(snapshot)

    def run_expiry(self) -> list[dict[str, Any]]:
        with self._lock:
            now = self.clock()
            results = []
            for record in self.state.expired_actions(now):
                try:
                    snapshot = self.load_case(record["case_id"])
                except KeyError:
                    snapshot = None
                try:
                    receipt = self.responder.remove(record["action_id"], reason="expired")
                except ResponseError as exc:
                    if snapshot is None:
                        results.append({"action_id": record["action_id"], "result": "failed"})
                        continue
                    self._audit(snapshot, "error", details={"code": "rollback_failed", "priority": "high",
                                                            "action_id": record["action_id"], "error": str(exc)[:300]})
                    self._notify(snapshot, kind="rollback_failure", recipients=[self.settings.analyst_address],
                                 subject=f"[SOAR HIGH] expiry removal failed for {record['action_id']}",
                                 text=f"Block {record['target']} (scope {record['scope']}) could not be removed: "
                                      f"{exc}. It stays active and will be retried; remove it manually if needed.")
                    self._save(snapshot)
                    results.append({"action_id": record["action_id"], "result": "failed"})
                    continue
                if snapshot is not None:
                    self._record_rollback(snapshot, receipt, SYSTEM_ACTOR)
                results.append({"action_id": record["action_id"], "result": receipt["result"],
                                "rollback_id": record["rollback_id"]})
            return results

    def rollback(self, action_or_rollback_id: str, *, analyst: str, reason: str) -> dict[str, Any]:
        if not analyst.strip() or len(reason.strip()) < 10:
            raise ApprovalError("missing_reason", "manual rollback requires analyst and a reason")
        with self._lock:
            record = self.state.get_action(action_or_rollback_id)
            if record is None:
                raise KeyError(action_or_rollback_id)
            snapshot = self.load_case(record["case_id"])
            receipt = self.responder.remove(record["action_id"], reason=f"manual: {reason.strip()[:200]}")
            if receipt["result"] != "already_removed":
                self._record_rollback(snapshot, receipt, _analyst_actor(analyst.strip()))
            return receipt
