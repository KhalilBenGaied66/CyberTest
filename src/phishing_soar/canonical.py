"""Indicator canonicalization, scope classification and safe display.

Canonical values are used for matching and caching only. The original evidence
value is always preserved alongside, and nothing here resolves, fetches or
follows anything.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit


class IndicatorError(ValueError):
    """A value cannot be turned into a trustworthy indicator."""


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")

DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

# Approximation of the Public Suffix List for organizational-domain checks.
# Good enough for a lab; production should use the PSL.
MULTI_PART_SUFFIXES = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "co.in", "co.za",
        "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "com.tn",
    }
)

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
SUPPORTED_URL_SCHEMES = frozenset(DEFAULT_PORTS)


def canonical_domain(value: str) -> str:
    """Lowercase, strip one trailing dot, IDNA-encode labels and validate."""
    text = value.strip()
    if text.endswith("."):
        text = text[:-1]
    if not text or ".." in text or len(text) > 253:
        raise IndicatorError(f"invalid domain {value!r}")
    labels = []
    for label in text.split("."):
        if label.isascii():
            ascii_label = label.lower()
        else:
            try:
                ascii_label = label.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise IndicatorError(f"invalid IDN label in {value!r}") from exc
        if not _LABEL_RE.match(ascii_label):
            raise IndicatorError(f"invalid domain label in {value!r}")
        labels.append(ascii_label)
    result = ".".join(labels)
    if len(result) > 253:
        raise IndicatorError(f"domain too long: {value!r}")
    return result


def domain_display(ascii_domain: str) -> str:
    """Unicode rendering of a Punycode domain, for analyst display only."""
    labels = []
    for label in ascii_domain.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def has_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def canonical_ip(value: str) -> str:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if text.lower().startswith("ipv6:"):
        text = text[5:]
    if "%" in text:
        raise IndicatorError("scoped IPv6 addresses are not supported")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise IndicatorError(f"invalid IP address {value!r}") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def is_ip(value: str) -> bool:
    try:
        canonical_ip(value)
    except IndicatorError:
        return False
    return True


def ip_scope(value: str) -> str:
    """Classify an IP: public, documentation, private, loopback, link_local, multicast..."""
    ip = ipaddress.ip_address(value)
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if any(ip.version == net.version and ip in net for net in DOCUMENTATION_NETWORKS):
        return "documentation"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "public"
    return "reserved"


def is_routable(value: str, *, lab_doc_ranges_routable: bool) -> bool:
    """True for public IPs; documentation ranges count only in explicit lab-fixture mode."""
    scope = ip_scope(value)
    return scope == "public" or (scope == "documentation" and lab_doc_ranges_routable)


@lru_cache(maxsize=256)
def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def ip_in_networks(value: str, networks: tuple[str, ...]) -> bool:
    ip = ipaddress.ip_address(value)
    for cidr in networks:
        net = _network(cidr)
        if net.version == ip.version and ip in net:
            return True
    return False


def domain_matches(domain: str, patterns: tuple[str, ...]) -> bool:
    """Exact match or subdomain match against a list of canonical domains."""
    return any(domain == p or domain.endswith("." + p) for p in patterns)


def organizational_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass(frozen=True)
class UrlParts:
    normalized: str
    scheme: str
    host: str
    host_type: str  # "domain" | "ip"
    port: int | None  # only when non-default
    has_userinfo: bool
    warnings: tuple[str, ...]


def canonical_url(value: str) -> UrlParts:
    """Normalize a URL for matching without changing the evidence value.

    Lowercases scheme/host, IDNA-encodes the host, drops default ports, userinfo
    and fragments, and preserves path and query exactly. Never follows redirects.
    """
    raw = value.strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise IndicatorError(f"unparseable URL {value!r}") from exc
    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_URL_SCHEMES:
        raise IndicatorError(f"unsupported URL scheme {scheme!r}")
    host_raw = parts.hostname
    if not host_raw:
        raise IndicatorError(f"URL without host {value!r}")
    warnings: list[str] = []
    try:
        host = canonical_ip(host_raw)
        host_type = "ip"
    except IndicatorError:
        host = canonical_domain(host_raw)
        host_type = "domain"
    has_userinfo = parts.username is not None or parts.password is not None
    if has_userinfo:
        warnings.append("url_userinfo_removed_for_matching")
    if parts.fragment:
        warnings.append("url_fragment_removed_for_matching")
    netloc = f"[{host}]" if ":" in host else host
    kept_port = port if port is not None and port != DEFAULT_PORTS[scheme] else None
    if kept_port is not None:
        netloc = f"{netloc}:{kept_port}"
    path = parts.path or "/"
    normalized = f"{scheme}://{netloc}{path}"
    if parts.query:
        normalized += f"?{parts.query}"
    return UrlParts(normalized, scheme, host, host_type, kept_port, has_userinfo, tuple(warnings))


def canonical_email(value: str) -> str:
    text = value.strip().strip("<>").strip()
    if not _EMAIL_RE.match(text):
        raise IndicatorError(f"invalid email address {value!r}")
    local, _, domain = text.rpartition("@")
    return f"{local.lower()}@{canonical_domain(domain)}"


def canonical_sha256(value: str) -> str:
    text = value.strip().lower()
    if not _SHA256_RE.match(text):
        raise IndicatorError("invalid SHA-256 value")
    return text


_REFANG_REPLACEMENTS = (
    ("[://]", "://"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[@]", "@"),
    ("[at]", "@"),
)
_HXXP_RE = re.compile(r"^h(?:xx|XX)p", re.IGNORECASE)


def refang(value: str) -> tuple[str, bool]:
    """Undo common defanging. Returns (value, changed)."""
    out = value
    for old, new in _REFANG_REPLACEMENTS:
        out = out.replace(old, new)
    out = _HXXP_RE.sub("http", out)
    return out, out != value


def defang(value: str) -> str:
    """Make an indicator non-clickable for tickets, cards and notifications."""
    out = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    out = re.sub(r"^ftp", "fxp", out, flags=re.IGNORECASE)
    return out.replace(".", "[.]").replace("@", "[@]")
