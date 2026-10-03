from conftest import approve, eml, wazuh_fixture


def test_replayed_email_links_to_original_and_never_reacts(pipeline):
    first = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    approve(pipeline, first)
    second = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    assert second["duplicate"] is True
    assert second["case_id"] == first["case_id"]
    assert second["result"] == "duplicate_suppressed"
    assert "approval" not in second  # no new decision can be requested
    snapshot = pipeline.load_case(first["case_id"])
    assert len(snapshot["duplicates"]) == 1
    assert len(pipeline.state.actions_for_case(first["case_id"])) == 1
    events = [e["event_type"] for e in pipeline.audit.case_events(first["case_id"])]
    assert events.count("duplicate_suppressed") == 1 and events.count("action") == 1
    assert len(list((pipeline.root / "cases").iterdir())) == 1


def test_duplicate_does_not_re_enrich(pipeline, replay):
    pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    calls = len(replay.calls)
    pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    assert len(replay.calls) == calls


def test_replayed_wazuh_alert_is_suppressed(pipeline):
    first = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    second = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    third = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    assert first["case_id"] == second["case_id"] == third["case_id"]
    assert third["occurrence"] == 3


def test_same_content_after_window_is_a_new_case(pipeline, clock):
    first = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    clock.advance(24 * 3600 + 1)
    second = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    assert second["duplicate"] is False and second["case_id"] != first["case_id"]


def test_pending_case_is_also_deduplicated(pipeline):
    first = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    second = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    assert second["case_id"] == first["case_id"] and second["status"] == "awaiting_approval"
