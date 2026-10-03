import io
import zipfile
from email.message import EmailMessage

import pytest

from conftest import P1_HOST, P1_URL, P2_SHA256, eml
from phishing_soar.config import Policy
from phishing_soar.email_parser import interpret_authentication, parse_eml, parse_received


@pytest.fixture
def p1(policy):
    return parse_eml(eml("p1_credential_harvest.eml"), policy)


def test_p1_headers_and_encoded_subject(p1):
    assert p1.subject == "Action required: your Microsoft 365 password expires today"
    assert p1.from_display == "Microsoft Support"
    assert p1.from_address == "support@login-example.test"
    assert p1.return_path == "bounce@mailer-example.test"
    assert p1.reply_to == "helpdesk@reply-example.test"
    assert p1.date == "2026-10-03T07:11:45.000Z"
    assert not p1.partial


def test_p1_trusted_authentication_results_ignore_forged_copy(p1):
    auth = p1.authentication
    assert auth["trust"] == "trusted"
    assert auth["authserv_id"] == "mx.lab.example"
    assert (auth["spf"], auth["dkim"], auth["dmarc"]) == ("fail", "none", "fail")
    assert "mail.login-example.test" in auth["ignored_authserv_ids"]


def test_p1_received_chain_trust_labels(p1):
    trust = [(hop["by_host"], hop["trust"], hop["ips"]) for hop in p1.received]
    assert trust == [
        ("mailstore.lab.example", "trusted_internal", ["10.0.0.25"]),
        ("mx.lab.example", "trusted_boundary", ["203.0.113.10"]),
        ("mailer-example.test", "untrusted", ["198.51.100.200"]),
    ]


def test_p1_urls_deduplicated_with_link_mismatch(p1):
    normalized = {u["normalized"] for u in p1.urls}
    assert normalized == {P1_URL}
    href = next(u for u in p1.urls if u["source"] == "html_href")
    assert href["link_text"] == "portal.example.com"
    assert {"link_text_mismatch", "punycode_host"} <= set(href["flags"])
    assert href["host"] == P1_HOST
    assert {"password expires", "verify your account", "sign in"} <= set(p1.credential_phrases)


def test_p2_attachment_hash_and_flags(policy):
    parsed = parse_eml(eml("p2_malicious_attachment.eml"), policy)
    [attachment] = parsed.attachments
    assert attachment["filename"] == "invoice.docm"
    assert attachment["sha256"] == P2_SHA256
    assert attachment["detected_type"] == "zip"
    assert {"macro_office", "mime_extension_mismatch"} <= set(attachment["flags"])
    assert "magic_extension_mismatch" not in attachment["flags"]
    assert parsed.authentication["dkim"] == "pass_aligned"


def test_truncated_message_is_partial_not_a_crash(policy):
    parsed = parse_eml(eml("p1_truncated.eml"), policy)
    assert parsed.partial
    assert any(w.startswith("mime_defect:") for w in parsed.warnings)
    assert parsed.from_address == "support@login-example.test"


def _message(**headers) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = headers.get("From", "Sender <sender@example.test>")
    msg["To"] = "victim@lab.example"
    msg["Subject"] = headers.get("Subject", "test")
    msg["Date"] = "Sat, 03 Oct 2026 07:00:00 +0000"
    msg["Message-ID"] = "<t@example.test>"
    return msg


def test_attachments_double_extension_executable_magic_and_encrypted_zip():
    msg = _message()
    msg.set_content("see attached")
    msg.add_attachment(b"MZ\x90\x00fake-pe", maintype="application", subtype="pdf", filename="statement.pdf.exe")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", "inert")
    data = bytearray(buffer.getvalue())
    data[6] |= 0x1  # local header: encrypted flag
    central = data.find(b"PK\x01\x02")
    data[central + 8] |= 0x1  # central directory: encrypted flag
    msg.add_attachment(bytes(data), maintype="application", subtype="zip", filename="docs.zip")
    parsed = parse_eml(msg.as_bytes(), Policy())
    by_name = {a["filename"]: a for a in parsed.attachments}
    assert {"executable", "double_extension", "mime_extension_mismatch"} <= set(by_name["statement.pdf.exe"]["flags"])
    assert "password_protected_archive" in by_name["docs.zip"]["flags"]


def test_hidden_executable_content_is_flagged_by_magic():
    msg = _message()
    msg.set_content("report")
    msg.add_attachment(b"MZ\x90\x00", maintype="application", subtype="pdf", filename="report.pdf")
    [attachment] = parse_eml(msg.as_bytes(), Policy()).attachments
    assert {"executable", "executable_content_hidden", "magic_extension_mismatch"} <= set(attachment["flags"])


def test_shortener_port_ip_literal_and_defanged_urls():
    msg = _message()
    msg.set_content(
        "a https://bit.ly/abc b http://198.51.100.9:8080/x c hxxps://evil-example[.]test/path d http://user:pw@host.test/"
    )
    parsed = parse_eml(msg.as_bytes(), Policy())
    flags = {u["normalized"]: set(u["flags"]) for u in parsed.urls}
    assert "url_shortener" in flags["https://bit.ly/abc"]
    assert {"nonstandard_port", "ip_literal_host"} <= flags["http://198.51.100.9:8080/x"]
    assert "defanged_in_source" in flags["https://evil-example.test/path"]
    assert "embedded_credentials" in flags["http://host.test/"]
    assert any(w.startswith("defanged_indicator_refanged") for w in parsed.warnings)


def test_html_data_and_javascript_urls_are_flagged_not_decoded():
    msg = _message()
    msg.set_content('<a href="javascript:alert(1)">x</a><img src="data:image/png;base64,AAAA">', subtype="html")
    parsed = parse_eml(msg.as_bytes(), Policy())
    assert parsed.urls == []
    assert any(w.startswith("data_url_present") for w in parsed.warnings)
    assert any(w.startswith("javascript_url_present") for w in parsed.warnings)


def test_multiple_from_and_missing_headers_become_warnings():
    raw = (b"From: a@one.test\r\nFrom: b@two.test\r\nSubject: hi\r\n\r\nbody\r\n")
    parsed = parse_eml(raw, Policy())
    assert parsed.from_address == "a@one.test"
    assert {"multiple_from_headers", "missing_message_id", "missing_date"} <= set(parsed.warnings)


def test_no_body_and_missing_from_is_partial():
    parsed = parse_eml(b"Subject: nothing here\r\n\r\n", Policy())
    assert parsed.partial
    assert {"missing_from_header", "no_body"} <= set(parsed.warnings)


def test_nested_message_is_hashed_not_parsed():
    inner = _message(Subject="inner")
    inner.set_content("inner body https://inner.example.test/")
    outer = _message(Subject="outer")
    outer.set_content("forwarded")
    outer.add_attachment(inner)
    parsed = parse_eml(outer.as_bytes(), Policy())
    nested = [a for a in parsed.attachments if "nested_message_not_parsed" in a["flags"]]
    assert len(nested) == 1 and len(nested[0]["sha256"]) == 64
    assert all("inner.example.test" not in u["normalized"] for u in parsed.urls)


def test_ipv6_received_hop():
    hops = parse_received(
        ["from relay.test (relay.test [IPv6:2001:db8::25]) by mx.lab.example with ESMTPS; Sat, 3 Oct 2026"],
        Policy(trusted_mta_hosts=("mx.lab.example",)),
    )
    assert hops[0]["ips"] == ["2001:db8::25"]
    assert hops[0]["trust"] == "trusted_boundary"


def test_authentication_results_trust_modes():
    headers = ["evil.test; spf=pass; dmarc=pass", "mx.lab.example; spf=softfail smtp.mailfrom=x@a.test; dmarc=none"]
    trusted = interpret_authentication(headers, "a.test", Policy(trusted_authserv_ids=("mx.lab.example",)))
    assert (trusted["trust"], trusted["spf"], trusted["dmarc"]) == ("trusted", "softfail", "none")
    untrusted = interpret_authentication(headers[:1], "a.test", Policy(trusted_authserv_ids=("mx.lab.example",)))
    assert untrusted["trust"] == "untrusted" and untrusted["spf"] is None
    assumed = interpret_authentication(headers, "a.test", Policy())
    assert assumed["trust"] == "assumed_topmost" and assumed["authserv_id"] == "evil.test"


def test_dkim_alignment():
    headers = ["mx.lab.example; dkim=pass header.d=esp.example; dkim=fail header.d=a.test"]
    summary = interpret_authentication(headers, "a.test", Policy(trusted_authserv_ids=("mx.lab.example",)))
    assert summary["dkim"] == "pass_unaligned"
