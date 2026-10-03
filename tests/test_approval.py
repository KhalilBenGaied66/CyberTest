import pytest

from conftest import P1_HOST, approve, eml, load_schema, reject, wazuh_fixture
from phishing_soar.approval import ApprovalError


def test_approve_creates_audited_temporary_block(pipeline):
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"), reporter="alex.analyst@lab.example")
    outcome = approve(pipeline, result)
    assert outcome["result"] == "decision_recorded"
    assert outcome["outcome"] == "responded" and outcome["status"] == "audited"
    [receipt] = outcome["actions"]
    assert (receipt["target"], receipt["result"], receipt["verified"], receipt["mode"]) == (
        P1_HOST, "success", True, "simulate")
    events = pipeline.audit.case_events(result["case_id"])
    decision = next(e for e in events if e["event_type"] == "decision")
    action = next(e for e in events if e["event_type"] == "action")
    assert decision["sequence"] < action["sequence"]
    assert action["decision"]["proposed_action_hash"] == decision["decision"]["proposed_action_hash"]
    assert decision["actor"] == {"type": "analyst", "id": "analyst-lab", "display": "analyst-lab"}
    kinds = [n["kind"] for n in pipeline.load_case(result["case_id"])["notifications"]]
    assert kinds == ["analyst_card", "analyst_response", "reporter_closure"]


def test_reject_never_contains(pipeline):
    result = pipeline.ingest_email(eml("p3_benign_saas.eml"), reporter="alex.analyst@lab.example")
    outcome = reject(pipeline, result)
    assert outcome["outcome"] == "closed" and outcome["actions"] == []
    assert pipeline.state.actions_for_case(result["case_id"]) == []


def test_reject_of_high_case_never_contains(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    outcome = reject(pipeline, result, verdict="suspicious_no_action",
                     reason="Source IP belongs to the authorised red-team exercise")
    assert outcome["outcome"] == "closed"
    assert pipeline.state.actions_for_case(result["case_id"]) == []


def test_timeout_creates_no_containment_and_escalates(pipeline, clock):
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    clock.advance(29 * 60)
    assert pipeline.sweep_timeouts() == []
    clock.advance(61)
    [handled] = pipeline.sweep_timeouts()
    assert handled["case_id"] == result["case_id"]
    snapshot = pipeline.load_case(result["case_id"])
    assert snapshot["outcome"] == "needs_review" and snapshot["status"] == "audited"
    assert snapshot["decision"]["approval"] == "timeout"
    assert pipeline.state.actions_for_case(result["case_id"]) == []
    assert "escalation" in [n["kind"] for n in snapshot["notifications"]]
    late = approve(pipeline, result)
    assert late["result"] == "decision_already_recorded"
    assert pipeline.state.actions_for_case(result["case_id"]) == []


def test_decision_after_expiry_but_before_sweep_is_timeout(pipeline, clock):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    clock.advance(31 * 60)
    outcome = approve(pipeline, result)
    assert outcome["result"] == "approval_expired" and outcome["outcome"] == "needs_review"
    assert pipeline.state.actions_for_case(result["case_id"]) == []


def test_double_click_is_idempotent(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    approve(pipeline, result)
    again = approve(pipeline, result)
    assert again["result"] == "decision_already_recorded"
    assert len(pipeline.state.actions_for_case(result["case_id"])) == 1
    switched = reject(pipeline, result)
    assert switched["result"] == "decision_already_recorded"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"decision": "approve", "verdict": "malicious", "reason": "short", "analyst": "a"}, "missing_reason"),
        ({"decision": "approve", "verdict": "benign", "reason": "x" * 20, "analyst": "a"}, "invalid_verdict"),
        ({"decision": "reject", "verdict": "malicious", "reason": "x" * 20, "analyst": "a"}, "invalid_verdict"),
        ({"decision": "approve", "verdict": "malicious", "reason": "x" * 20, "analyst": "a",
          "approved_actions": ["act-000000000000"]}, "invalid_action"),
        ({"decision": "reject", "verdict": "benign", "reason": "x" * 20, "analyst": "a",
          "approved_actions": ["act-000000000000"]}, "invalid_action"),
        ({"decision": "maybe", "verdict": "malicious", "reason": "x" * 20, "analyst": "a"}, "invalid_decision"),
        ({"decision": "approve", "verdict": "malicious", "reason": "x" * 20}, "missing_analyst"),
        ({"decision": "approve", "verdict": "malicious", "reason": "x" * 20, "analyst": "a",
          "proposed_action_hash": "sha256:" + "0" * 64}, "action_hash_mismatch"),
    ],
)
def test_invalid_decisions_change_nothing(pipeline, payload, code):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    with pytest.raises(ApprovalError) as info:
        pipeline.decide(result["case_id"], result["approval"]["token"], payload)
    assert info.value.code == code
    assert pipeline.load_case(result["case_id"])["status"] == "awaiting_approval"
    assert approve(pipeline, result)["result"] == "decision_recorded"  # still decidable afterwards


def test_low_score_case_cannot_approve_containment(pipeline):
    result = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    assert result["proposed_actions"] == []
    with pytest.raises(ApprovalError) as info:
        approve(pipeline, result, actions=["act-1234567890ab"])
    assert info.value.code == "invalid_action"


def test_forged_callback_token_is_refused_and_audited(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    with pytest.raises(ApprovalError) as info:
        pipeline.decide(result["case_id"], "forged-token", {
            "decision": "approve", "verdict": "malicious", "reason": "x" * 20, "analyst": "mallory",
            "approved_actions": [a["action_id"] for a in result["proposed_actions"]]})
    assert info.value.code == "invalid_callback_token"
    assert pipeline.state.actions_for_case(result["case_id"]) == []
    errors = [e for e in pipeline.audit.case_events(result["case_id"]) if e["event_type"] == "error"]
    assert errors[-1]["details"]["code"] == "invalid_callback_token"


def test_token_is_bound_to_its_case(pipeline):
    first = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    second = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    with pytest.raises(ApprovalError):
        pipeline.decide(second["case_id"], first["approval"]["token"], {
            "decision": "approve", "verdict": "malicious", "reason": "x" * 20, "analyst": "a"})


def test_approve_without_selecting_actions_records_verdict_only(pipeline):
    result = pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    outcome = approve(pipeline, result, reason="Macro dropper confirmed by hash; no blockable target")
    assert outcome["outcome"] == "responded" and outcome["actions"] == []
    assert outcome["decision"]["verdict"] == "malicious"


def test_decision_records_match_schema(pipeline, clock):
    jsonschema = pytest.importorskip("jsonschema")
    schema = load_schema("approval.schema.json")
    approved = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    rejected = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    timed_out = pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    jsonschema.validate(approve(pipeline, approved)["decision"], schema)
    jsonschema.validate(reject(pipeline, rejected)["decision"], schema)
    clock.advance(1801)
    pipeline.sweep_timeouts()
    jsonschema.validate(pipeline.load_case(timed_out["case_id"])["decision"], schema)


def test_approval_token_never_persisted(pipeline):
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    approve(pipeline, result)
    token = result["approval"]["token"]
    for path in pipeline.root.rglob("*"):
        if path.is_file():
            assert token.encode() not in path.read_bytes(), path


def test_internal_failure_cancels_approval_and_sweep_continues(pipeline, clock, monkeypatch):
    import phishing_soar.pipeline as pipeline_module
    from phishing_soar.pipeline import PipelineError

    healthy = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    original = pipeline_module.render_card

    def broken(snapshot):
        raise RuntimeError("ticket template bug")

    monkeypatch.setattr(pipeline_module, "render_card", broken)
    with pytest.raises(PipelineError) as info:
        pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    monkeypatch.setattr(pipeline_module, "render_card", original)
    failed = pipeline.load_case(info.value.case_id)
    assert failed["status"] == "failed_needs_review" and info.value.stage == "approval_request"
    clock.advance(1801)
    handled = pipeline.sweep_timeouts()
    assert [h["case_id"] for h in handled] == [healthy["case_id"]]
    assert pipeline.load_case(info.value.case_id)["status"] == "failed_needs_review"
