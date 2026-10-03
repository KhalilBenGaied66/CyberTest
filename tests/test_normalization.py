import json

import pytest

from conftest import P1_HOST, P1_URL, P2_SHA256, W1_IP, eml, load_schema, wazuh_fixture
from phishing_soar.config import Policy
from phishing_soar.email_parser import normalize_email
from phishing_soar.models import NormalizedCase
from phishing_soar.wazuh_normalizer import (
    WazuhIntakeError,
    check_rule_allowed,
    load_wazuh_payload,
    normalize_wazuh,
    wazuh_dedupe_key,
)

jsonschema = pytest.importorskip("jsonschema")

RAW_REF = {"path": "cases/x/raw/y", "sha256": "0" * 64, "size": 10, "kind": "eml"}
CASE_ID = "07a747f6-a10e-4fe4-a51b-8e9ace184729"


def _email_case(settings, name="p1_credential_harvest.eml"):
    return normalize_email(eml(name), case_id=CASE_ID, received_at="2026-10-03T07:12:00.000Z",
                           reporter="alex.analyst@lab.example", reported_at=None, raw_ref=RAW_REF,
                           settings=settings)


def _wazuh_case(settings, name="w1_bruteforce_success.json"):
    alert, envelope = load_wazuh_payload(wazuh_fixture(name), max_bytes=settings.max_wazuh_bytes)
    return normalize_wazuh(alert, envelope, case_id=CASE_ID, received_at="2026-10-03T07:12:00.000Z",
                           raw_ref={**RAW_REF, "kind": "wazuh_alert"}, settings=settings)


def test_both_sources_share_top_level_contract(settings):
    email_case = _email_case(settings).to_dict()
    wazuh_case = _wazuh_case(settings).to_dict()
    assert email_case.keys() == wazuh_case.keys()
    schema = load_schema("normalized-case.schema.json")
    jsonschema.validate(email_case, schema)
    jsonschema.validate(wazuh_case, schema)


def test_email_indicators_have_provenance(settings):
    case = _email_case(settings)
    by_value = {(i.type, i.normalized_value): i for i in case.indicators}
    url = by_value[("url", P1_URL)]
    assert url.origin == "body" and len(url.occurrences) == 2  # text part and HTML href
    assert url.safe_display.startswith("hxxps://")
    assert ("domain", P1_HOST) in by_value
    assert ("domain", "login-example.test") in by_value
    boundary = by_value[("ip", "203.0.113.10")]
    assert boundary.scoring_eligible and "trusted_boundary" in boundary.first_seen_in
    forged_hop = by_value[("ip", "198.51.100.200")]
    assert not forged_hop.scoring_eligible
    assert ("ip", "10.0.0.25") not in by_value  # private relay IPs are evidence only
    internal = by_value[("domain", "lab.example")] if ("domain", "lab.example") in by_value else None
    assert internal is None or not internal.external_lookup_allowed


def test_email_attachment_hash_indicator(settings):
    case = _email_case(settings, "p2_malicious_attachment.eml")
    hashes = [i for i in case.indicators if i.type == "sha256"]
    assert [h.normalized_value for h in hashes] == [P2_SHA256]
    assert hashes[0].first_seen_in == "attachment:invoice.docm"


def test_round_trip_serialization(settings):
    case = _email_case(settings)
    again = NormalizedCase.from_dict(json.loads(json.dumps(case.to_dict())))
    assert again == case


def test_wazuh_mapping(settings):
    case = _wazuh_case(settings)
    wazuh = case.evidence["wazuh"]
    assert case.source_event_id == "wazuh-lab-manager:1759454304.88421"
    assert case.observed_at == "2026-10-03T01:18:22.000Z"
    assert wazuh["behavior"] == {"authentication_failures_5m": 18, "distinct_users_5m": 3,
                                 "success_after_failures": True, "counts_source": "integration"}
    assert case.entities["user"] == "root"
    assert [i.normalized_value for i in case.indicators] == [W1_IP]
    assert case.parse_warnings == []


def test_wazuh_counts_derived_from_previous_output(settings):
    case = _wazuh_case(settings, "w2_bare_alert_previous_output.json")
    behavior = case.evidence["wazuh"]["behavior"]
    assert behavior["authentication_failures_5m"] == 12
    assert behavior["distinct_users_5m"] == 4
    assert behavior["success_after_failures"] is None
    assert "failure_count_derived_from_previous_output" in case.parse_warnings


def test_wazuh_missing_rule_id_rejected(settings):
    with pytest.raises(WazuhIntakeError) as info:
        load_wazuh_payload(wazuh_fixture("invalid_missing_rule_id.json"), max_bytes=settings.max_wazuh_bytes)
    assert info.value.code == "missing_rule_id"


def test_wazuh_rule_allowlist(settings):
    alert, _ = load_wazuh_payload(wazuh_fixture("invalid_rule_not_allowlisted.json"), max_bytes=1 << 20)
    with pytest.raises(WazuhIntakeError) as info:
        check_rule_allowed(alert, Policy())
    assert info.value.code == "rule_not_allowlisted"


@pytest.mark.parametrize(("payload", "code"), [(b"", "empty_payload"), (b"[1]", "invalid_payload"),
                                               (b"{not json", "invalid_json"), (b"x" * 300, "payload_too_large")])
def test_wazuh_payload_validation(payload, code):
    with pytest.raises(WazuhIntakeError) as info:
        load_wazuh_payload(payload, max_bytes=256)
    assert info.value.code == code


def test_wazuh_unfamiliar_layout_is_warning_not_crash(settings):
    alert = {"rule": {"id": "5712", "level": 10}, "data": "unexpected"}
    case = normalize_wazuh(alert, {}, case_id=CASE_ID, received_at="2026-10-03T07:12:00.000Z",
                           raw_ref=RAW_REF, settings=settings)
    assert "normalization_warning:missing_data_object" in case.parse_warnings
    assert "missing_alert_id_fallback_hash" in case.parse_warnings
    assert case.indicators == []


def test_wazuh_dedupe_key_is_manager_plus_alert_id():
    key_a, _, _ = wazuh_dedupe_key({"id": "1", "manager": {"name": "m"}, "rule": {"id": "5712"}})
    key_b, _, _ = wazuh_dedupe_key({"id": "1", "manager": {"name": "m"}, "rule": {"id": "5712"}, "extra": 1})
    key_c, _, _ = wazuh_dedupe_key({"id": "1", "manager": {"name": "other"}, "rule": {"id": "5712"}})
    assert key_a == key_b != key_c


def test_private_wazuh_source_ip_is_not_enriched_externally(settings):
    alert = {"id": "9", "rule": {"id": "5712", "level": 10}, "data": {"srcip": "10.9.8.7", "dstuser": "bob"}}
    case = normalize_wazuh(alert, {}, case_id=CASE_ID, received_at="2026-10-03T07:12:00.000Z",
                           raw_ref=RAW_REF, settings=settings)
    [indicator] = case.indicators
    assert not indicator.external_lookup_allowed
    assert "source_ip_not_public:private" in case.parse_warnings
