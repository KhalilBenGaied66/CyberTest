import json
import threading
import uuid

import pytest

from conftest import approve, eml, load_schema, reject, wazuh_fixture
from phishing_soar.audit import AuditLedger, AuditWriteError, verify_chain


def _run_all_paths(pipeline, clock):
    p1 = pipeline.ingest_email(eml("p1_credential_harvest.eml"), reporter="alex.analyst@lab.example")
    approve(pipeline, p1)
    p3 = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    reject(pipeline, p3)
    w1 = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    approve(pipeline, w1)
    pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))  # duplicate
    pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    clock.advance(3600)
    pipeline.sweep_timeouts()
    pipeline.run_expiry()
    return p1, w1


def test_chain_verifies_across_all_paths(pipeline, clock):
    _run_all_paths(pipeline, clock)
    report = verify_chain(pipeline.root / "audit")
    assert report["ok"], report["errors"]
    assert report["events"] > 30 and report["cases"] == 4


def test_tampering_is_detected(pipeline, clock):
    _run_all_paths(pipeline, clock)
    [ledger] = (pipeline.root / "audit").glob("events-*.jsonl")
    lines = ledger.read_text().splitlines()
    event = json.loads(lines[5])
    event["details"]["tampered"] = True
    lines[5] = json.dumps(event)
    ledger.write_text("\n".join(lines) + "\n")
    errors = verify_chain(pipeline.root / "audit")["errors"]
    assert {"event_hash_mismatch"} <= {e["error"] for e in errors}


def test_deleted_line_is_detected(pipeline, clock):
    _run_all_paths(pipeline, clock)
    [ledger] = (pipeline.root / "audit").glob("events-*.jsonl")
    lines = ledger.read_text().splitlines()
    del lines[3]
    ledger.write_text("\n".join(lines) + "\n")
    assert {"broken_link"} <= {e["error"] for e in verify_chain(pipeline.root / "audit")["errors"]}


def test_every_event_matches_schema(pipeline, clock):
    jsonschema = pytest.importorskip("jsonschema")
    schema = load_schema("audit-event.schema.json")
    _run_all_paths(pipeline, clock)
    [ledger] = (pipeline.root / "audit").glob("events-*.jsonl")
    for line in ledger.read_text().splitlines():
        jsonschema.validate(json.loads(line), schema)


def test_secrets_and_tokens_are_redacted(tmp_path, clock):
    ledger = AuditLedger(tmp_path / "audit", tmp_path / "cases", secrets=("super-secret-key-1234",), clock=clock)
    case_id = str(uuid.uuid4())
    event = ledger.append(case_id, "error", details={"token": "abc", "note": "key=super-secret-key-1234",
                                                     "nested": {"Authorization": "Bearer x"}})
    assert event["details"] == {"token": "[REDACTED]", "note": "key=[REDACTED]", "nested": {"Authorization": "[REDACTED]"}}
    raw = (tmp_path / "audit").glob("*.jsonl")
    assert all(b"super-secret-key-1234" not in p.read_bytes() for p in raw)


def test_concurrent_writes_keep_a_valid_chain(tmp_path, clock):
    ledger = AuditLedger(tmp_path / "audit", tmp_path / "cases", clock=clock)
    case_ids = [str(uuid.uuid4()) for _ in range(4)]

    def writer(case_id):
        for _ in range(25):
            ledger.append(case_id, "notification", details={"n": 1})

    threads = [threading.Thread(target=writer, args=(c,)) for c in case_ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    report = verify_chain(tmp_path / "audit")
    assert report["ok"], report["errors"]
    assert report["events"] == 100
    assert [e["sequence"] for e in ledger.case_events(case_ids[0])] == list(range(1, 26))


def test_audit_write_failure_is_never_silent(tmp_path, clock):
    ledger = AuditLedger(tmp_path / "audit", tmp_path / "cases", clock=clock)
    case_id = str(uuid.uuid4())
    (tmp_path / "cases" / case_id).mkdir(parents=True)
    (tmp_path / "cases" / case_id / "events.jsonl").mkdir()  # a directory where the file should be
    with pytest.raises(AuditWriteError):
        ledger.append(case_id, "received")


def test_case_can_be_reconstructed_from_its_events(pipeline, clock):
    p1, _ = _run_all_paths(pipeline, clock)
    events = pipeline.audit.case_events(p1["case_id"])
    kinds = [e["event_type"] for e in events]
    assert kinds[:5] == ["received", "normalized", "enriched", "scored", "notification"]
    assert {"approval_requested", "decision", "action", "closed", "rollback"} <= set(kinds)
    scored = next(e for e in events if e["event_type"] == "scored")
    assert scored["score"]["total"] == 74
    assert sum(f["points"] for f in scored["score"]["factors"]) == 74
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))


def test_intake_rejection_is_audited(pipeline):
    from phishing_soar.pipeline import IntakeError

    for payload, code in ((b"", "empty_file"), (b"x" * (pipeline.settings.max_eml_bytes + 1), "too_large")):
        with pytest.raises(IntakeError) as info:
            pipeline.ingest_email(payload)
        assert info.value.code == code
        [event] = pipeline.audit.case_events(info.value.case_id)
        assert event["event_type"] == "error" and event["details"]["code"] == code
