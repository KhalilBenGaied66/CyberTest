import copy

import pytest

from conftest import P1_HOST, W1_IP, eml, wazuh_fixture
from phishing_soar.config import Policy
from phishing_soar.enrichment.engine import EnrichmentReport
from phishing_soar.models import EnrichmentResult, NormalizedCase
from phishing_soar.scoring import band_for, recompute_total, score_case


def _factors(pipeline, case_id):
    score = pipeline.load_case(case_id)["score"]
    return {f["factor_id"]: f["applied_points"] for f in score["factors"]}, score


def test_p1_credential_harvest_scores_74_high(pipeline):
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    factors, score = _factors(pipeline, result["case_id"])
    assert factors == {
        "rep_exact": 30, "rep_corrob": 5,
        "auth_dmarc_fail": 10, "auth_spf_fail": 5,
        "id_return_path_mismatch": 5, "id_reply_to_mismatch": 5,
        "content_deceptive_link": 8, "content_credential_lure": 6,
    }
    assert (score["total"], score["band"], score["model_version"]) == (74, "high", "email-1.0")
    assert {c: v["applied"] for c, v in score["categories"].items()} == {
        "reputation": 35, "authentication": 15, "identity": 10, "content": 14}
    assert recompute_total(score) == 74 == sum(f["applied_points"] for f in score["factors"])
    [action] = score["proposed_actions"]
    assert (action["type"], action["target"], action["ttl_seconds"]) == ("temporary_domain_block", P1_HOST, 3600)
    assert score["recommended_verdict"] == "malicious"


def test_p2_malicious_attachment_with_passing_auth_scores_53_medium(pipeline):
    result = pipeline.ingest_email(eml("p2_malicious_attachment.eml"))
    factors, score = _factors(pipeline, result["case_id"])
    assert factors == {"rep_exact": 30, "rep_corrob": 5, "content_dangerous_attachment": 12,
                       "content_attachment_type_mismatch": 6}
    assert (score["total"], score["band"]) == (53, "medium")
    assert score["proposed_actions"] == []  # no hash-capable containment in the core lab
    assert any("not proof of benign" in o for o in score["observations"])


def test_p3_benign_scores_5_low(pipeline):
    result = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    factors, score = _factors(pipeline, result["case_id"])
    assert factors == {"id_return_path_mismatch": 5}
    assert (score["total"], score["band"], score["recommended_verdict"]) == (5, "low", "likely_benign")
    assert score["proposed_actions"] == []


def test_w1_bruteforce_then_success_scores_90_high(pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    factors, score = _factors(pipeline, result["case_id"])
    assert factors == {"rep_exact": 35, "rep_corrob": 5, "auth_fail_burst": 15, "multi_user": 10,
                       "success_after_fail": 15, "privileged_user": 10}
    assert (score["total"], score["band"], score["model_version"]) == (90, "high", "wazuh-1.0")
    [action] = score["proposed_actions"]
    assert (action["type"], action["target"], action["scope"]) == ("temporary_ip_block", W1_IP, "agent:linux-lab-01")


def test_p1_offline_scores_69_high_local_only(settings, make_pipeline):
    from conftest import MANIFEST
    from phishing_soar.enrichment.replay import ReplayTransport

    pipeline = make_pipeline(settings, ReplayTransport(MANIFEST, fail_with="timeout"))
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    assert result["score"]["total"] == 69 and result["score"]["band"] == "high"
    assert result["enrichment"] == {"mode": "offline", "completeness": "local_only"}
    score = pipeline.load_case(result["case_id"])["score"]
    assert {u["check"] for u in score["unknowns"]} >= {"urlhaus", "threatfox"}
    assert result["status"] == "awaiting_approval"


def test_display_name_impersonation_is_policy_driven(settings, make_pipeline):
    policy = Policy.from_mapping({**{k: list(v) for k, v in vars(settings.policy).items()},
                                  "protected_display_names": ["microsoft"]})
    pipeline = make_pipeline(settings.with_overrides(policy=policy))
    result = pipeline.ingest_email(eml("p1_credential_harvest.eml"))
    factors, score = _factors(pipeline, result["case_id"])
    assert factors["id_display_name_impersonation"] == 5
    assert score["total"] == 79


@pytest.mark.parametrize(("total", "band"), [(0, "low"), (29, "low"), (30, "medium"), (59, "medium"),
                                             (60, "high"), (100, "high")])
def test_band_boundaries(total, band):
    assert band_for(total) == band


def _wazuh_case(behavior, *, user="bob", level=10, srcip="203.0.113.150"):
    return NormalizedCase(
        case_id="11111111-2222-3333-4444-555555555555", source_type="wazuh", source_event_id="m:1",
        received_at="2026-10-03T07:12:00.000Z", observed_at=None, status="normalized",
        entities={"reporter": None, "user": user, "agent": {"id": "002", "name": "web-lab-01"}},
        indicators=[], parse_warnings=[], dedupe_key="0" * 64,
        raw_ref={"path": "x", "sha256": "0" * 64, "size": 1, "kind": "wazuh_alert"},
        evidence={"wazuh": {"rule": {"id": "5712", "level": level, "description": "test"},
                            "agent": {"id": "002", "name": "web-lab-01"}, "source_ip": srcip, "user": user,
                            "behavior": {"counts_source": "integration", **behavior}}},
    )


def _empty_report():
    return EnrichmentReport(results=[], provider_health={}, provider_reasons={}, completeness_ratio=1.0,
                            completeness="complete", enrichment_mode="online", local_feed_age_hours=0)


def _email_case(*, dmarc=None, spf=None, return_path_org=None, reply_to_org=None, attachments=(), urls=(),
                phrases=(), hash_indicator=False):
    from phishing_soar.indicators import IndicatorCollector

    collector = IndicatorCollector(Policy(), lab_doc_ranges_routable=True)
    if hash_indicator:
        collector.add("sha256", "ab" * 32, origin="attachment", location="attachment:x")
    mailbox = lambda org: {"address": f"x@{org}", "display_name": None, "domain": org, "org_domain": org}  # noqa: E731
    return NormalizedCase(
        case_id="11111111-2222-3333-4444-555555555556", source_type="email", source_event_id="sha256:0",
        received_at="2026-10-03T07:12:00.000Z", observed_at=None, status="normalized",
        entities={"reporter": None, "user": None, "agent": None}, indicators=collector.results(),
        parse_warnings=[], dedupe_key="0" * 64, raw_ref={"path": "x", "sha256": "0" * 64, "size": 1, "kind": "eml"},
        evidence={"email": {
            "authentication": {"trust": "trusted", "authserv_id": "mx.lab.example", "spf": spf, "spf_domain": "s.test",
                               "dkim": "none", "dmarc": dmarc},
            "from": mailbox("sender.test"),
            "return_path": mailbox(return_path_org) if return_path_org else None,
            "reply_to": mailbox(reply_to_org) if reply_to_org else None,
            "attachments": [{"filename": "a", "declared_mime": "x", "flags": list(f)} for f in attachments],
            "urls": [{"normalized": "https://u.test/", "link_text": None, "flags": list(f)} for f in urls],
            "credential_phrases": list(phrases),
        }},
    )


def _malicious_report(case, sources=("local_ioc", "threatfox")):
    results = [EnrichmentResult(provider=p, indicator_id=i.indicator_id, indicator_type=i.type,
                                indicator_value=i.normalized_value, status="ok", match=True, verdict="malicious")
               for i in case.indicators for p in sources]
    report = _empty_report()
    report.results = results
    return report


@pytest.mark.parametrize(
    ("kwargs", "malicious", "total", "band"),
    [
        ({"spf": "softfail", "attachments": [["macro_office", "double_extension"]], "urls": [["punycode_host"]]},
         False, 29, "low"),
        ({"dmarc": "fail", "attachments": [["executable"]], "urls": [["ip_literal_host"]]}, False, 30, "medium"),
        ({"dmarc": "fail", "spf": "softfail", "return_path_org": "rp.test", "urls": [[]],
          "phrases": ["sign in"], "hash_indicator": True}, True, 59, "medium"),
        ({"dmarc": "fail", "spf": "fail", "return_path_org": "rp.test", "reply_to_org": "rt.test",
          "hash_indicator": True}, True, 60, "high"),
    ],
)
def test_score_boundaries_29_30_59_60(settings, kwargs, malicious, total, band):
    case = _email_case(**kwargs)
    report = _malicious_report(case) if malicious else _empty_report()
    score = score_case(case, report, settings)
    assert (score.total, score.band) == (total, band)
    assert recompute_total(score.to_dict()) == total


def test_wazuh_level_fallback_only_without_counts(settings):
    no_counts = _wazuh_case({"authentication_failures_5m": None, "distinct_users_5m": None,
                             "success_after_failures": None})
    score = score_case(no_counts, _empty_report(), settings)
    ids = {f["factor_id"] for f in score.factors}
    assert "high_severity_no_counts" in ids
    with_counts = _wazuh_case({"authentication_failures_5m": 3, "distinct_users_5m": None,
                               "success_after_failures": None})
    assert "high_severity_no_counts" not in {f["factor_id"] for f in score_case(with_counts, _empty_report(), settings).factors}


def test_category_caps_and_recompute(settings):
    case = _wazuh_case({"authentication_failures_5m": 50, "distinct_users_5m": 9, "success_after_failures": True},
                       user="svc-backup")
    score = score_case(case, _empty_report(), settings).to_dict()
    assert score["categories"]["behavior"] == {"cap": 40, "raw": 40, "applied": 40}
    assert recompute_total(score) == score["total"] == sum(f["applied_points"] for f in score["factors"])


def test_unknown_enrichment_adds_zero_and_never_subtracts(pipeline, settings):
    result = pipeline.ingest_email(eml("p3_benign_saas.eml"))
    snapshot = pipeline.load_case(result["case_id"])
    case = NormalizedCase.from_dict(snapshot["case"])
    report = EnrichmentReport.from_dict(snapshot["enrichment"])
    degraded = copy.deepcopy(report)
    for r in degraded.results:
        if r.provider != "local_ioc" and r.status == "ok":
            r.status, r.match, r.verdict, r.reason = "unknown", None, None, "timeout"
    degraded.provider_reasons = {"urlhaus": ["timeout"]}
    assert score_case(case, degraded, settings).total == score_case(case, report, settings).total == 5


def test_duplicate_provider_evidence_does_not_inflate(settings, pipeline):
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    snapshot = pipeline.load_case(result["case_id"])
    case = NormalizedCase.from_dict(snapshot["case"])
    report = EnrichmentReport.from_dict(snapshot["enrichment"])
    ip = case.indicators[0]
    report.results.append(EnrichmentResult(provider="urlhaus", indicator_id=ip.indicator_id, indicator_type="ip",
                                           indicator_value=ip.normalized_value, status="ok", match=True,
                                           verdict="malicious"))
    score = score_case(case, report, settings)
    reputation = score.categories["reputation"]
    assert reputation["raw"] == 40 and reputation["applied"] == 40
    assert score.total == 90


def test_allowlist_conflict_suppresses_block(settings, make_pipeline):
    policy = Policy.from_mapping({**{k: list(v) for k, v in vars(settings.policy).items()},
                                  "allowlist_networks": ["198.51.100.44/32"]})
    pipeline = make_pipeline(settings.with_overrides(policy=policy))
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    assert result["proposed_actions"] == []
    assert "allowlist_conflict" in result["flags"]
    assert result["score"]["total"] == 90  # allowlist never erases the evidence
    outcome = pipeline.decide(result["case_id"], result["approval"]["token"], {
        "decision": "approve", "verdict": "malicious", "reason": "Malicious despite allowlist entry",
        "analyst": "analyst-lab", "approved_actions": []})
    assert outcome["outcome"] == "needs_review" and outcome["actions"] == []


def test_protected_target_is_never_proposed(settings, make_pipeline):
    policy = Policy.from_mapping({**{k: list(v) for k, v in vars(settings.policy).items()},
                                  "protected_networks": ["198.51.100.0/24"]})
    pipeline = make_pipeline(settings.with_overrides(policy=policy))
    result = pipeline.ingest_wazuh(wazuh_fixture("w1_bruteforce_success.json"))
    assert result["proposed_actions"] == []
    assert any(f.startswith("containment_suppressed:protected_network") for f in result["flags"])
