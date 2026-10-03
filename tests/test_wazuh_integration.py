import importlib.util
import json

from conftest import REPO, W1_IP, wazuh_fixture
from phishing_soar.wazuh_normalizer import load_wazuh_payload

spec = importlib.util.spec_from_file_location("custom_soar", REPO / "wazuh" / "shuffle-integration.example.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)


def test_integration_forwards_only_selected_fields_in_lab_envelope():
    alert = json.loads(wazuh_fixture("w1_bruteforce_success.json"))["alert"]
    alert["data"]["password"] = "never-forward-me"
    alert["syscheck"] = {"path": "/etc/shadow"}
    selected = integration.select_fields(alert)
    assert "password" not in selected["data"] and "syscheck" not in selected
    envelope = {"schema_version": "1.0", "source": "wazuh", "sent_at": "2026-10-03T01:18:24Z", "alert": selected}
    parsed, meta = load_wazuh_payload(json.dumps(envelope).encode(), max_bytes=256 * 1024)
    assert parsed["data"]["srcip"] == W1_IP and meta["source"] == "wazuh"


def test_integration_truncates_large_logs():
    alert = {"rule": {"id": "5712"}, "full_log": "x" * 10000, "previous_output": "y" * 100000}
    selected = integration.select_fields(alert)
    assert len(selected["full_log"]) == integration.MAX_LOG_CHARS
    assert len(selected["previous_output"]) == integration.MAX_PREVIOUS_OUTPUT_CHARS
