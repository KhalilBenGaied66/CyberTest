from conftest import NOW
from phishing_soar.enrichment.mirror import convert_threatfox_export


def test_threatfox_export_conversion():
    export = {
        "1": [{"ioc_value": "198.51.100.9:443", "ioc_type": "ip:port", "confidence_level": 75,
               "first_seen_utc": "2026-10-01 10:00:00", "tags": "cobalt,c2", "malware_printable": "Lab"}],
        "2": [{"ioc_value": "Bad-Example.TEST", "ioc_type": "domain", "confidence_level": 100}],
        "3": [{"ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash", "confidence_level": 100}],
        "4": [{"ioc_value": "low.example", "ioc_type": "domain", "confidence_level": 10}],
        "5": [{"ioc_value": "not a url", "ioc_type": "url", "confidence_level": 90}],
    }
    entries, counters = convert_threatfox_export(export, now=NOW, ttl_days=7)
    assert [(e["type"], e["value"]) for e in entries] == [("domain", "bad-example.test"), ("ip", "198.51.100.9")]
    ip = entries[1]
    assert ip["first_seen"] == "2026-10-01T10:00:00.000Z"
    assert ip["expires_at"] == "2026-10-10T07:12:00.000Z"
    assert ip["tags"] == ["Lab", "c2", "cobalt"]
    assert counters == {"rows": 5, "kept": 2, "skipped_type": 1, "skipped_confidence": 1, "invalid": 1}
