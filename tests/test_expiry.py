import json

import pytest

from conftest import W1_IP, approve, wazuh_fixture
from phishing_soar.response import ResponseError, UnsafeTargetError
from phishing_soar.response.safety import check_block_target, check_ttl


def _approved_w1(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    outcome = approve(pipeline, result, reason="Brute force followed by privileged login; exact IOC corroborated")
    return result, outcome["actions"][0]


def test_block_expires_after_ttl_and_is_audited(pipeline, clock):
    result, receipt = _approved_w1(pipeline)
    assert receipt["target"] == W1_IP and receipt["scope"] == "agent:linux-lab-01"
    clock.advance(3599)
    assert pipeline.run_expiry() == []
    clock.advance(1)
    [expired] = pipeline.run_expiry()
    assert expired["result"] == "success" and expired["rollback_id"] == receipt["rollback_id"]
    assert pipeline.state.active_action("temporary_ip_block", W1_IP, "agent:linux-lab-01") is None
    rollback = [e for e in pipeline.audit.case_events(result["case_id"]) if e["event_type"] == "rollback"]
    assert rollback[0]["action"]["removal_reason"] == "expired"
    oplog = [json.loads(line) for line in (pipeline.root / "blocklist" / "temporary_blocks.jsonl").read_text().splitlines()]
    assert [op["op"] for op in oplog] == ["add", "remove"]
    assert pipeline.run_expiry() == []


def test_accelerated_ttl_rollback(settings, make_pipeline, clock):
    pipeline = make_pipeline(settings.with_overrides(block_ttl_seconds=60))
    _, receipt = _approved_w1(pipeline)
    clock.advance(60)
    [expired] = pipeline.run_expiry()
    assert expired["rollback_id"] == receipt["rollback_id"]


def test_manual_rollback_is_idempotent_and_audited(pipeline):
    result, receipt = _approved_w1(pipeline)
    removed = pipeline.rollback(receipt["rollback_id"], analyst="analyst-lab", reason="False positive after VPN check")
    assert removed["result"] == "success" and removed["verified"]
    again = pipeline.rollback(receipt["rollback_id"], analyst="analyst-lab", reason="False positive after VPN check")
    assert again["result"] == "already_removed"
    rollbacks = [e for e in pipeline.audit.case_events(result["case_id"]) if e["event_type"] == "rollback"]
    assert len(rollbacks) == 1 and rollbacks[0]["actor"]["type"] == "analyst"


def test_duplicate_action_links_to_existing_block(pipeline):
    _approved_w1(pipeline)
    alert = json.loads(wazuh_fixture("w1_bruteforce_success.json"))
    alert["alert"]["id"] = "1759454304.99999"
    second = pipeline.ingest_wazuh(json.dumps(alert).encode())
    outcome = approve(pipeline, second)
    [receipt] = outcome["actions"]
    assert receipt["result"] == "already_active" and receipt["linked_action_id"]
    assert len(pipeline.state.actions_for_case(second["case_id"])) == 0


def test_forced_add_failure_needs_review(pipeline):
    pipeline.responder.fail_add = True
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    outcome = approve(pipeline, result)
    assert outcome["outcome"] == "response_failed_needs_review"
    assert outcome["actions"] == []
    errors = [e for e in pipeline.audit.case_events(result["case_id"]) if e["event_type"] == "error"]
    assert errors[0]["details"]["code"] == "response_failed" and errors[0]["details"]["priority"] == "high"
    kinds = [n["kind"] for n in pipeline.load_case(result["case_id"])["notifications"]]
    assert "response_failure" in kinds


def test_forced_remove_failure_keeps_block_and_alerts(pipeline, clock):
    result, receipt = _approved_w1(pipeline)
    pipeline.responder.fail_remove = True
    clock.advance(3600)
    assert pipeline.run_expiry() == [{"action_id": receipt["action_id"], "result": "failed"}]
    assert pipeline.state.active_action("temporary_ip_block", W1_IP, "agent:linux-lab-01") is not None
    kinds = [n["kind"] for n in pipeline.load_case(result["case_id"])["notifications"]]
    assert "rollback_failure" in kinds
    pipeline.responder.fail_remove = False
    assert pipeline.run_expiry()[0]["result"] == "success"


def test_notification_failure_marks_response_partial(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    pipeline.notifier.fail = True
    outcome = approve(pipeline, result)
    assert outcome["outcome"] == "response_partial"
    assert outcome["actions"][0]["result"] == "success"


@pytest.mark.parametrize(
    ("target_type", "target", "reason"),
    [
        ("ip", "10.0.0.5", "non_public_ip:private"),
        ("ip", "127.0.0.1", "non_public_ip:loopback"),
        ("ip", "203.0.113.1", "protected_network"),
        ("ip", "203.0.113.200", "allowlisted"),
        ("domain", "mail.lab.example", "internal_domain"),
        ("domain", "partner-portal.example", "allowlisted"),
        ("domain", "bit.ly", "shared_infrastructure"),
        ("domain", "localhost", "single_label_domain"),
        ("hash", "abc", "unsupported_target_type"),
    ],
)
def test_protected_targets_are_refused(policy, target_type, target, reason):
    with pytest.raises(UnsafeTargetError) as info:
        check_block_target(target_type, target, policy, lab_doc_ranges_routable=True)
    assert info.value.reason == reason


def test_documentation_ranges_need_explicit_lab_mode(policy):
    with pytest.raises(UnsafeTargetError):
        check_block_target("ip", W1_IP, policy, lab_doc_ranges_routable=False)
    assert check_block_target("ip", W1_IP, policy, lab_doc_ranges_routable=True) == W1_IP


@pytest.mark.parametrize("ttl", [0, -5, 3601, 86400])
def test_ttl_is_capped_at_sixty_minutes(ttl):
    with pytest.raises(UnsafeTargetError):
        check_ttl(ttl)


def test_adapter_refuses_tampered_action(pipeline):
    with pytest.raises(UnsafeTargetError):
        pipeline.responder.add("case", {"action_id": "act-x", "type": "temporary_ip_block", "target": "10.0.0.1",
                                        "scope": "agent:x", "ttl_seconds": 60})
    with pytest.raises(ResponseError):
        pipeline.responder.remove("rb-does-not-exist", reason="manual")
