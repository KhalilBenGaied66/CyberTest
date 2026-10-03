import json

import pytest

from conftest import FIXTURES, MANIFEST, P1_URL, W1_IP, Clock, load_schema
from phishing_soar.config import Policy
from phishing_soar.enrichment import Enricher, LocalIocIndex
from phishing_soar.enrichment.base import HttpResponse, TransportError
from phishing_soar.enrichment.replay import ReplayTransport
from phishing_soar.indicators import IndicatorCollector
from phishing_soar.state import StateStore


def indicators(*items):
    collector = IndicatorCollector(Policy(), lab_doc_ranges_routable=True)
    for ind_type, value in items:
        collector.add(ind_type, value, origin="body", location="test")
    return collector.results()


@pytest.fixture
def state(tmp_path):
    return StateStore(tmp_path / "soar.db")


@pytest.fixture
def local():
    return LocalIocIndex([FIXTURES / "local_iocs.jsonl"])


def make(settings, state, local, transport, clock=None):
    return Enricher(settings, state, local, transport=transport, clock=clock or Clock(), sleep=lambda _: None)


def by_provider(report, provider):
    return [r for r in report.results if r.provider == provider]


def test_local_exact_hit_and_remote_corroboration(settings, state, local):
    report = make(settings, state, local, ReplayTransport(MANIFEST)).enrich(indicators(("url", P1_URL)))
    [local_result] = by_provider(report, "local_ioc")
    [urlhaus] = by_provider(report, "urlhaus")
    assert (local_result.match, local_result.verdict) == (True, "malicious")
    assert (urlhaus.status, urlhaus.match, urlhaus.verdict) == ("ok", True, "malicious")
    assert urlhaus.raw_ref.startswith("sha256:")
    assert report.enrichment_mode == "online" and report.completeness == "complete"
    assert report.provider_health["virustotal"] == "disabled"


def test_local_miss_and_provider_no_result_are_answers(settings, state, local):
    report = make(settings, state, local, ReplayTransport(MANIFEST)).enrich(indicators(("domain", "unknown.example")))
    for result in report.results:
        assert result.status == "ok" and result.match is False


def test_total_network_loss_is_unknown_never_clean(settings, state, local):
    transport = ReplayTransport(MANIFEST, fail_with="timeout")
    report = make(settings, state, local, transport).enrich(indicators(("url", P1_URL), ("ip", W1_IP)))
    remote = [r for r in report.results if r.provider != "local_ioc" and r.status != "not_applicable"]
    assert remote and all(r.status == "unknown" and r.match is None and r.verdict is None for r in remote)
    assert all(r.status == "ok" for r in by_provider(report, "local_ioc"))
    assert report.enrichment_mode == "offline" and report.completeness == "local_only"
    assert report.provider_health["urlhaus"] == "unavailable"


def test_timeout_retries_once_then_circuit_opens(settings, state, local):
    calls = []

    def flaky(request):
        calls.append(request.url)
        raise TransportError("timeout")

    enricher = make(settings, state, local, flaky)
    enricher.enrich(indicators(("domain", "a.example")))
    assert len(calls) == 4  # one jittered retry each for URLhaus and ThreatFox
    calls.clear()
    enricher.enrich(indicators(("domain", "b.example")))
    assert len(calls) == 2  # third failure within five minutes opens the circuit; no retry
    calls.clear()
    report = enricher.enrich(indicators(("domain", "c.example")))
    assert calls == []
    assert {r.reason for r in report.results if r.provider != "local_ioc"} == {"circuit_open"}


def test_http_429_honours_retry_after_without_retrying(settings, state, local):
    calls = []

    def limited(request):
        calls.append(request.url)
        return HttpResponse(429, {"Retry-After": "120"}, b"")

    clock = Clock()
    enricher = make(settings, state, local, limited, clock)
    report = enricher.enrich(indicators(("domain", "a.example"), ("domain", "b.example")))
    assert len(calls) == 2  # one call per provider, then skipped for the rest of the case
    reasons = [r.reason for r in report.results if r.provider == "urlhaus"]
    assert reasons == ["rate_limited", "circuit_open"]
    clock.advance(121)
    calls.clear()
    enricher.enrich(indicators(("domain", "c.example")))
    assert len(calls) == 2


def test_malformed_json_and_5xx(settings, state, local):
    def broken(request):
        if "urlhaus" in request.url:
            return HttpResponse(200, {}, b"<html>not json</html>")
        return HttpResponse(503, {}, b"")

    report = make(settings, state, local, broken).enrich(indicators(("domain", "a.example")))
    reasons = {r.provider: r.reason for r in report.results}
    assert reasons["urlhaus"] == "malformed_response"
    assert reasons["threatfox"] == "http_503"


def test_cache_hit_avoids_second_call(settings, state, local):
    transport = ReplayTransport(MANIFEST)
    enricher = make(settings, state, local, transport)
    enricher.enrich(indicators(("url", P1_URL)))
    first = len(transport.calls)
    report = enricher.enrich(indicators(("url", P1_URL)))
    assert len(transport.calls) == first
    assert report.cache_hits == 2


def test_not_configured_provider_is_unknown(settings, state, local):
    unconfigured = settings.with_overrides(urlhaus_auth_key=None)
    report = make(unconfigured, state, local, ReplayTransport(MANIFEST)).enrich(indicators(("url", P1_URL)))
    [urlhaus] = by_provider(report, "urlhaus")
    assert (urlhaus.status, urlhaus.reason) == ("unknown", "not_configured")
    assert report.enrichment_mode == "degraded"


def test_offline_setting_never_calls_transport(settings, state, local):
    def explode(request):
        raise AssertionError("network used while offline")

    report = make(settings.with_overrides(offline=True), state, local, explode).enrich(indicators(("ip", W1_IP)))
    assert report.enrichment_mode == "offline"


def test_stale_local_ioc_is_marked_stale(settings, state, local):
    report = make(settings, state, local, ReplayTransport(MANIFEST)).enrich(indicators(("domain", "stale-example.test")))
    [result] = by_provider(report, "local_ioc")
    assert (result.match, result.verdict) == (True, "stale")


def test_private_scope_is_skipped_but_local_lookup_still_runs(settings, state, local):
    collector = IndicatorCollector(Policy(), lab_doc_ranges_routable=False)
    collector.add("ip", "10.1.2.3", origin="wazuh", location="test")
    report = make(settings, state, local, ReplayTransport(MANIFEST)).enrich(collector.results())
    statuses = {r.provider: r.status for r in report.results}
    assert statuses == {"local_ioc": "ok", "urlhaus": "skipped", "threatfox": "skipped"}


def test_conflicting_providers_are_kept_side_by_side(settings, state, local, tmp_path):
    manifest = json.loads(MANIFEST.read_text())
    manifest["responses"].append({"provider": "urlhaus", "key": W1_IP, "body": {"query_status": "no_results"}})
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    for name in ("urlhaus_no_results.json", "threatfox_no_result.json", "threatfox_ip_w1.json"):
        (tmp_path / name).write_bytes((MANIFEST.parent / name).read_bytes())
    report = make(settings, state, local, ReplayTransport(path)).enrich(indicators(("ip", W1_IP)))
    verdicts = {r.provider: r.verdict for r in report.results}
    assert verdicts == {"local_ioc": "malicious", "urlhaus": "no_result", "threatfox": "malicious"}


def test_virustotal_disabled_by_default_and_budgeted_when_enabled(settings, state, local):
    calls = []

    def vt(request):
        calls.append(request.url)
        if "virustotal" in request.url:
            body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "harmless": 50}}}}
            return HttpResponse(200, {}, json.dumps(body).encode())
        return ReplayTransport(MANIFEST)(request)

    enabled = settings.with_overrides(vt_enabled=True, vt_api_key="test-vt-key-0003", vt_per_minute=1)
    report = make(enabled, state, local, vt).enrich(indicators(("domain", "a.example"), ("domain", "b.example")))
    vt_results = by_provider(report, "virustotal")
    assert vt_results[0].verdict == "malicious"
    assert vt_results[1].reason == "budget_exhausted"
    assert sum("virustotal" in c for c in calls) == 1


def test_enrichment_results_match_schema(settings, state, local):
    jsonschema = pytest.importorskip("jsonschema")
    schema = load_schema("enrichment-result.schema.json")
    report = make(settings, state, local, ReplayTransport(MANIFEST, fail_with="timeout")).enrich(
        indicators(("url", P1_URL), ("ip", W1_IP), ("email", "a@b.example"))
    )
    for result in report.results:
        jsonschema.validate(result.to_dict(), schema)
