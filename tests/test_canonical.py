import pytest

from phishing_soar.canonical import (
    IndicatorError,
    canonical_domain,
    canonical_email,
    canonical_ip,
    canonical_sha256,
    canonical_url,
    defang,
    domain_display,
    ip_scope,
    organizational_domain,
    refang,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("pоrtal-example.test", "xn--prtal-example-i7k.test"),  # Cyrillic "о"
        ("münchen.example", "xn--mnchen-3ya.example"),
        ("sub.Domain.Example", "sub.domain.example"),
    ],
)
def test_canonical_domain(raw, expected):
    assert canonical_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "bad..domain", "-lead.example", "under score.example", "a" * 64 + ".example"])
def test_canonical_domain_rejects(raw):
    with pytest.raises(IndicatorError):
        canonical_domain(raw)


def test_domain_display_round_trip():
    assert domain_display("xn--prtal-example-i7k.test") == "pоrtal-example.test"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("IPv6:2001:db8::2", "2001:db8::2"),
        ("::ffff:198.51.100.44", "198.51.100.44"),
        (" 198.51.100.44 ", "198.51.100.44"),
    ],
)
def test_canonical_ip(raw, expected):
    assert canonical_ip(raw) == expected


@pytest.mark.parametrize("raw", ["010.1.1.1", "fe80::1%eth0", "300.1.1.1", "example.com"])
def test_canonical_ip_rejects_ambiguous(raw):
    with pytest.raises(IndicatorError):
        canonical_ip(raw)


@pytest.mark.parametrize(
    ("ip", "scope"),
    [
        ("8.8.8.8", "public"),
        ("10.1.2.3", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("198.51.100.44", "documentation"),
        ("2001:db8::1", "documentation"),
        ("0.0.0.0", "unspecified"),
    ],
)
def test_ip_scope(ip, scope):
    assert ip_scope(ip) == scope


def test_canonical_url_preserves_path_and_query_but_not_fragment_or_default_port():
    parts = canonical_url("HTTPS://User:Pass@Pоrtal-Example.TEST:443/Login?Session=8F2a#frag")
    assert parts.normalized == "https://xn--prtal-example-i7k.test/Login?Session=8F2a"
    assert parts.has_userinfo
    assert parts.port is None
    assert set(parts.warnings) == {"url_userinfo_removed_for_matching", "url_fragment_removed_for_matching"}


def test_canonical_url_keeps_nondefault_port_and_ipv6():
    assert canonical_url("http://[2001:db8::5]:8080").normalized == "http://[2001:db8::5]:8080/"
    parts = canonical_url("http://198.51.100.9:8443/x")
    assert parts.host_type == "ip" and parts.port == 8443


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "data:text/html;base64,AAAA", "https://", "http://[::1"])
def test_canonical_url_rejects(raw):
    with pytest.raises(IndicatorError):
        canonical_url(raw)


def test_defang_and_refang():
    assert defang("https://evil.example/a.php") == "hxxps://evil[.]example/a[.]php"
    assert defang("user@evil.example") == "user[@]evil[.]example"
    assert refang("hxxps://evil[.]example/path") == ("https://evil.example/path", True)
    assert refang("plain text") == ("plain text", False)


def test_email_and_hash():
    assert canonical_email("<Support@Login-Example.TEST>") == "support@login-example.test"
    assert canonical_sha256("AB" * 32) == "ab" * 32
    with pytest.raises(IndicatorError):
        canonical_sha256("xyz")


@pytest.mark.parametrize(
    ("domain", "org"),
    [
        ("mail.saas-mailer.example", "saas-mailer.example"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
    ],
)
def test_organizational_domain(domain, org):
    assert organizational_domain(domain) == org
