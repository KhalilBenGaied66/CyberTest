import base64
import json
import threading
import urllib.error
import urllib.request

import pytest

from conftest import eml, wazuh_fixture
from phishing_soar.service import build_server


@pytest.fixture
def api(pipeline):
    server = build_server(pipeline, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    token = pipeline.settings.api_token

    def call(method, path, body=b"", headers=None, auth=True):
        request = urllib.request.Request(base + path, data=body if method == "POST" else None, method=method)
        if auth:
            request.add_header("Authorization", f"Bearer {token}")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    yield call
    server.shutdown()
    server.server_close()


def test_healthz_is_unauthenticated(api):
    assert api("GET", "/healthz", auth=False) == (200, {"status": "ok"})


def test_missing_or_wrong_bearer_token_is_rejected(api):
    assert api("POST", "/v1/intake/wazuh", wazuh_fixture("w1_bruteforce_success.json"), auth=False)[0] == 401
    status, _ = api("GET", "/v1/cases/07a747f6-a10e-4fe4-a51b-8e9ace184729", headers={"Authorization": "Bearer nope"},
                    auth=False)
    assert status == 401


def test_email_raw_and_json_intake_then_decision(api):
    status, created = api("POST", "/v1/intake/email", eml("p1_credential_harvest.eml"),
                          headers={"Content-Type": "message/rfc822", "X-Reporter": "alex.analyst@lab.example"})
    assert status == 200 and created["score"]["total"] == 74
    status, duplicate = api("POST", "/v1/intake/email", json.dumps({
        "eml_base64": base64.b64encode(eml("p1_credential_harvest.eml")).decode()}).encode(),
        headers={"Content-Type": "application/json"})
    assert status == 200 and duplicate["duplicate"] and duplicate["case_id"] == created["case_id"]
    decision = {"token": created["approval"]["token"], "decision": "approve", "verdict": "malicious",
                "reason": "Exact URL match and DMARC fail; approve bounded block", "analyst": "analyst-lab",
                "approved_actions": [a["action_id"] for a in created["proposed_actions"]]}
    status, decided = api("POST", f"/v1/cases/{created['case_id']}/decision", json.dumps(decision).encode())
    assert status == 200 and decided["outcome"] == "responded"
    status, snapshot = api("GET", f"/v1/cases/{created['case_id']}")
    assert status == 200 and snapshot["status"] == "audited"
    assert created["approval"]["token"] not in json.dumps(snapshot)


def test_forged_token_returns_403(api):
    _, created = api("POST", "/v1/intake/wazuh", wazuh_fixture("w1_bruteforce_success.json"))
    body = json.dumps({"token": "forged", "decision": "approve", "verdict": "malicious", "reason": "x" * 20,
                       "analyst": "mallory"}).encode()
    status, error = api("POST", f"/v1/cases/{created['case_id']}/decision", body)
    assert (status, error["error"]) == (403, "invalid_callback_token")


def test_intake_validation_errors(api, pipeline):
    status, error = api("POST", "/v1/intake/wazuh", wazuh_fixture("invalid_missing_rule_id.json"))
    assert (status, error["error"]) == (400, "missing_rule_id") and error["case_id"]
    status, error = api("POST", "/v1/intake/email", b"", headers={"Content-Type": "message/rfc822"})
    assert (status, error["error"]) == (400, "empty_file")
    too_big = b"x" * (pipeline.settings.max_wazuh_bytes + 1)
    status, error = api("POST", "/v1/intake/wazuh", too_big)
    assert (status, error["error"]) == (413, "payload_too_large")
    status, error = api("GET", "/v1/cases/not-a-case")
    assert status == 404


def test_jobs_endpoints(api):
    assert api("POST", "/v1/jobs/approval-timeouts") == (200, {"handled": []})
    assert api("POST", "/v1/jobs/expire") == (200, {"handled": []})


def test_server_refuses_weak_token(pipeline):
    weak = pipeline.settings.with_overrides(api_token="short")
    pipeline.settings = weak
    with pytest.raises(SystemExit):
        build_server(pipeline, "127.0.0.1", 0)
