"""RFC 5322 / MIME parsing and email normalization.

The parser never renders HTML, never fetches or resolves anything, never
executes or extracts attachments, and never recursively parses nested
messages. It hashes decoded bytes, records provenance, and turns malformed
input into warnings plus a ``parse_partial`` status instead of an exception.
"""

from __future__ import annotations

import email.policy
import email.utils
import io
import re
import zipfile
from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import Any

from .canonical import (
    IndicatorError,
    canonical_domain,
    canonical_email,
    canonical_ip,
    canonical_url,
    domain_display,
    has_punycode,
    is_routable,
    organizational_domain,
    refang,
)
from .config import Policy, Settings
from .indicators import IndicatorCollector
from .models import NormalizedCase
from .util import iso, sha256_hex

# -- vocabularies -------------------------------------------------------------------------------

CREDENTIAL_PHRASES = (
    "verify your account",
    "verify your identity",
    "confirm your account",
    "confirm your identity",
    "password expires",
    "password will expire",
    "password has expired",
    "reset your password",
    "update your password",
    "sign in",
    "log in",
    "account will be suspended",
    "account suspended",
    "account has been locked",
    "unusual sign-in activity",
    "update your payment",
    "urgent action required",
)

EXECUTABLE_EXTENSIONS = frozenset(
    {"exe", "scr", "com", "pif", "cpl", "msi", "msp", "dll", "jar", "hta", "lnk", "appx"}
)
SCRIPT_EXTENSIONS = frozenset({"bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh"})
MACRO_OFFICE_EXTENSIONS = frozenset(
    {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
)
DISK_IMAGE_EXTENSIONS = frozenset({"iso", "img", "vhd", "vhdx"})
ACTIVE_MARKUP_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml", "svg"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "cab", "ace"})
DECOY_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png"}
)

EXPECTED_MIME: dict[str, frozenset[str]] = {
    "pdf": frozenset({"application/pdf"}),
    "doc": frozenset({"application/msword"}),
    "docx": frozenset(
        {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    ),
    "docm": frozenset({"application/vnd.ms-word.document.macroenabled.12"}),
    "xls": frozenset({"application/vnd.ms-excel"}),
    "xlsx": frozenset({"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}),
    "xlsm": frozenset({"application/vnd.ms-excel.sheet.macroenabled.12"}),
    "pptx": frozenset(
        {"application/vnd.openxmlformats-officedocument.presentationml.presentation"}
    ),
    "pptm": frozenset({"application/vnd.ms-powerpoint.presentation.macroenabled.12"}),
    "zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    "txt": frozenset({"text/plain"}),
    "csv": frozenset({"text/csv", "text/plain"}),
    "html": frozenset({"text/html"}),
    "htm": frozenset({"text/html"}),
    "svg": frozenset({"image/svg+xml"}),
    "png": frozenset({"image/png"}),
    "jpg": frozenset({"image/jpeg"}),
    "jpeg": frozenset({"image/jpeg"}),
    "gif": frozenset({"image/gif"}),
    "exe": frozenset(
        {"application/x-msdownload", "application/x-dosexec",
         "application/vnd.microsoft.portable-executable"}
    ),
}

_MAGIC = (
    (b"MZ", "pe"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
)
MAGIC_FAMILY_FOR_EXTENSION: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "docx": frozenset({"zip"}), "docm": frozenset({"zip"}),
    "xlsx": frozenset({"zip"}), "xlsm": frozenset({"zip"}),
    "pptx": frozenset({"zip"}), "pptm": frozenset({"zip"}),
    "zip": frozenset({"zip"}),
    "doc": frozenset({"ole"}), "xls": frozenset({"ole"}), "ppt": frozenset({"ole"}),
    "msi": frozenset({"ole"}),
    "exe": frozenset({"pe"}), "dll": frozenset({"pe"}), "scr": frozenset({"pe"}),
    "7z": frozenset({"7z"}), "rar": frozenset({"rar"}), "gz": frozenset({"gzip"}),
    "png": frozenset({"png"}), "jpg": frozenset({"jpeg"}), "jpeg": frozenset({"jpeg"}),
    "gif": frozenset({"gif"}),
}

SEVERE_DEFECTS = frozenset(
    {
        "StartBoundaryNotFoundDefect",
        "CloseBoundaryNotFoundDefect",
        "MultipartInvariantViolationDefect",
        "NoBoundaryInMultipartDefect",
        "MissingHeaderBodySeparatorDefect",
    }
)

MAX_DEPTH = 20
MAX_TEXT_CHARS = 2_000_000
MAX_LINK_TEXT = 200

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`]+")
_DEFANGED_URL_RE = re.compile(r"(?i)\bh(?:xx|XX)ps?(?:://|\[://\]|\[:\]//)[^\s<>\"'`]+")
_EMAIL_IN_TEXT_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?i)(?:https?://)?((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*[a-z0-9¡-￿])?\.)+"
    r"[a-z¡-￿]{2,63})"
)
_TRAILING_PUNCTUATION = ".,;:!?)]}'\""


# -- data classes -------------------------------------------------------------------------------


@dataclass
class ParsedEmail:
    message_sha256: str
    size: int
    subject: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    return_path: str | None = None
    reply_to: str | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    message_id: str | None = None
    date: str | None = None
    authentication: dict[str, Any] = field(default_factory=dict)
    received: list[dict[str, Any]] = field(default_factory=list)
    urls: list[dict[str, Any]] = field(default_factory=list)
    body_emails: list[str] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    credential_phrases: list[str] = field(default_factory=list)
    body_present: bool = False
    warnings: list[str] = field(default_factory=list)
    partial: bool = False

    def domain_of(self, address: str | None) -> str | None:
        if not address or "@" not in address:
            return None
        try:
            return canonical_domain(address.rpartition("@")[2])
        except IndicatorError:
            return None


# -- HTML extraction ----------------------------------------------------------------------------


class _HtmlExtractor(HTMLParser):
    _BLOCK_TAGS = frozenset({"p", "div", "br", "tr", "li", "td", "h1", "h2", "h3", "h4", "table"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []  # (kind, target, visible text)
        self.text: list[str] = []
        self.data_urls = 0
        self.javascript_urls = 0
        self._current: tuple[str, list[str]] | None = None
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "").strip() for k, v in attrs}
        if tag in ("script", "style"):
            self._skip_depth += 1
            return
        if tag in self._BLOCK_TAGS:
            self.text.append("\n")
        for attr in ("src", "href", "action"):
            target = values.get(attr, "")
            if target.lower().startswith("data:"):
                self.data_urls += 1
            elif target.lower().startswith("javascript:"):
                self.javascript_urls += 1
        if tag == "a":
            if self._current is not None:
                self._close_link()
            self._current = (values.get("href", ""), [])
        elif tag == "form" and values.get("action"):
            self.links.append(("form_action", values["action"], ""))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag == "a":
            self._close_link()

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._current is not None:
            self._close_link()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text.append(data)
        if self._current is not None:
            self._current[1].append(data)

    def close(self) -> None:
        super().close()
        if self._current is not None:
            self._close_link()

    def _close_link(self) -> None:
        assert self._current is not None
        href, parts = self._current
        self.links.append(("html_href", href, " ".join("".join(parts).split())[:MAX_LINK_TEXT]))
        self._current = None


# -- helpers ------------------------------------------------------------------------------------


def _header_values(msg: Message, name: str, warnings: list[str]) -> list[str]:
    try:
        values = msg.get_all(name) or []
        return [str(v).strip() for v in values]
    except Exception as exc:  # malformed header encodings must never crash intake
        warnings.append(f"header_unreadable:{name}:{type(exc).__name__}")
        return []


def _parse_mailbox(value: str | None, warnings: list[str], name: str) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    display, address = email.utils.parseaddr(value)
    address = address.strip()
    if not address:
        warnings.append(f"unparseable_address:{name}")
        return display or None, None
    try:
        return display.strip() or None, canonical_email(address)
    except IndicatorError:
        warnings.append(f"invalid_address:{name}")
        return display.strip() or None, None


def _strip_comments(value: str) -> str:
    out: list[str] = []
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif depth == 0:
            out.append(char)
    return "".join(out)


def parse_authentication_results(value: str) -> dict[str, Any]:
    """Parse one RFC 8601 Authentication-Results header into methods and properties."""
    cleaned = " ".join(_strip_comments(value).split())
    pieces = [piece.strip() for piece in cleaned.split(";")]
    authserv_id = pieces[0].split()[0].lower() if pieces and pieces[0] else None
    results = []
    for piece in pieces[1:]:
        tokens = piece.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        props = {}
        for token in tokens[1:]:
            if "=" in token:
                key, _, prop_value = token.partition("=")
                props[key.lower()] = prop_value.strip('"').lower()
        results.append({"method": method.lower().split("/")[0], "result": result.lower(), "props": props})
    return {"authserv_id": authserv_id, "results": results}


def interpret_authentication(
    headers: list[str], from_domain: str | None, policy: Policy
) -> dict[str, Any]:
    """Select the trusted Authentication-Results header and summarise SPF/DKIM/DMARC.

    Only the topmost header whose authserv-id belongs to our receiving
    infrastructure is trusted; copies further down may be attacker-supplied.
    """
    parsed = [parse_authentication_results(h) for h in headers]
    chosen = None
    trust = "absent"
    if parsed:
        if policy.trusted_authserv_ids:
            for item in parsed:
                if item["authserv_id"] in policy.trusted_authserv_ids:
                    chosen, trust = item, "trusted"
                    break
            if chosen is None:
                trust = "untrusted"
        else:
            chosen, trust = parsed[0], "assumed_topmost"
    summary: dict[str, Any] = {
        "trust": trust,
        "authserv_id": chosen["authserv_id"] if chosen else None,
        "headers_seen": len(parsed),
        "ignored_authserv_ids": [p["authserv_id"] for p in parsed if p is not chosen],
        "spf": None,
        "spf_domain": None,
        "dkim": None,
        "dkim_results": [],
        "dmarc": None,
    }
    if not chosen:
        return summary
    from_org = organizational_domain(from_domain)
    for res in chosen["results"]:
        method, result, props = res["method"], res["result"], res["props"]
        if method == "spf" and summary["spf"] is None:
            summary["spf"] = result
            summary["spf_domain"] = props.get("smtp.mailfrom", "").rpartition("@")[2] or None
        elif method == "dmarc" and summary["dmarc"] is None:
            summary["dmarc"] = result
        elif method == "dkim":
            domain = props.get("header.d") or (props.get("header.i", "").rpartition("@")[2] or None)
            aligned = bool(domain and from_org and organizational_domain(domain) == from_org)
            summary["dkim_results"].append({"result": result, "domain": domain, "aligned": aligned})
    dkim = summary["dkim_results"]
    if any(d["result"] == "pass" and d["aligned"] for d in dkim):
        summary["dkim"] = "pass_aligned"
    elif any(d["result"] == "pass" for d in dkim):
        summary["dkim"] = "pass_unaligned"
    elif any(d["result"] == "fail" for d in dkim):
        summary["dkim"] = "fail"
    elif dkim:
        summary["dkim"] = dkim[0]["result"]
    return summary


def _extract_ips(text: str) -> list[str]:
    candidates: list[str] = []
    for chunk in re.findall(r"\[([^\]]+)\]|\(([^)]*)\)", text):
        for token in re.split(r"[\s,]+", " ".join(chunk)):
            token = token.strip("[]()")
            if not token:
                continue
            try:
                ip = canonical_ip(token)
            except IndicatorError:
                continue
            if ip not in candidates:
                candidates.append(ip)
    return candidates


def parse_received(headers: list[str], policy: Policy) -> list[dict[str, Any]]:
    """Parse Received hops (index 0 = topmost) and label trust from our boundary.

    Hops added by trusted receiving hosts are trusted; the first trusted hop
    that received from an outside host is the boundary, and everything below
    it may be forged.
    """
    trusted_hosts = set(policy.trusted_mta_hosts or policy.trusted_authserv_ids)
    hops = []
    for index, value in enumerate(headers):
        text = " ".join(value.split())
        from_match = re.search(r"(?i)\bfrom\s+(.*?)(?=\s+by\s|\s+with\s|\s+id\s|;|$)", text)
        by_match = re.search(r"(?i)\bby\s+([^\s;()]+)", text)
        from_clause = from_match.group(1) if from_match else ""
        from_host = from_clause.split()[0].lower() if from_clause.split() else None
        stamp = text.rpartition(";")[2].strip() if ";" in text else None
        hops.append(
            {
                "index": index,
                "from_host": from_host,
                "by_host": by_match.group(1).lower() if by_match else None,
                "ips": _extract_ips(from_clause),
                "timestamp": stamp,
                "trust": "unverified",
            }
        )
    if not trusted_hosts:
        return hops
    boundary_seen = False
    for hop in hops:
        if boundary_seen:
            hop["trust"] = "untrusted"
        elif hop["by_host"] in trusted_hosts:
            if hop["from_host"] in trusted_hosts:
                hop["trust"] = "trusted_internal"
            else:
                hop["trust"] = "trusted_boundary"
                boundary_seen = True
        else:
            hop["trust"] = "untrusted"
            boundary_seen = True
    return hops


def _detect_magic(data: bytes) -> str | None:
    for signature, name in _MAGIC:
        if data.startswith(signature):
            return name
    head = data[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")):
        return "html"
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    return None


def _zip_encrypted(data: bytes) -> bool | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return any(info.flag_bits & 0x1 for info in archive.infolist()[:1000])
    except (zipfile.BadZipFile, ValueError, OSError, EOFError):
        return None


def _safe_filename(name: str | None) -> str | None:
    if not name:
        return None
    cleaned = "".join(ch if ch.isprintable() and ch not in "/\\" else "_" for ch in name)
    return cleaned.strip()[:255] or None


def analyze_attachment(
    filename: str | None, declared_mime: str, data: bytes, *, inline: bool, location: str
) -> dict[str, Any]:
    name = (filename or "").lower()
    stem_parts = [p.strip() for p in name.split(".")]
    extension = stem_parts[-1] if len(stem_parts) > 1 else None
    flags: list[str] = []
    if extension in EXECUTABLE_EXTENSIONS:
        flags.append("executable")
    if extension in SCRIPT_EXTENSIONS:
        flags.append("script")
    if extension in MACRO_OFFICE_EXTENSIONS:
        flags.append("macro_office")
    if extension in DISK_IMAGE_EXTENSIONS:
        flags.append("disk_image")
    if extension in ACTIVE_MARKUP_EXTENSIONS:
        flags.append("active_markup")
    magic = _detect_magic(data)
    if magic == "pe" and "executable" not in flags:
        flags.extend(["executable", "executable_content_hidden"])
    if len(stem_parts) >= 3 and stem_parts[-2] in DECOY_EXTENSIONS and extension not in DECOY_EXTENSIONS:
        flags.append("double_extension")
    if extension in EXPECTED_MIME and declared_mime.lower() not in EXPECTED_MIME[extension]:
        flags.append("mime_extension_mismatch")
    if extension in MAGIC_FAMILY_FOR_EXTENSION and magic and magic not in MAGIC_FAMILY_FOR_EXTENSION[extension]:
        flags.append("magic_extension_mismatch")
    if extension in ARCHIVE_EXTENSIONS:
        flags.append("archive")
        if magic == "zip":
            encrypted = _zip_encrypted(data)
            if encrypted:
                flags.append("password_protected_archive")
            elif encrypted is None:
                flags.append("archive_unreadable")
        else:
            flags.append("archive_encryption_unknown")
    return {
        "filename": _safe_filename(filename),
        "extension": extension,
        "declared_mime": declared_mime.lower(),
        "detected_type": magic,
        "size": len(data),
        "sha256": sha256_hex(data),
        "inline": inline,
        "location": location,
        "flags": flags,
    }


def _part_text(part: Message) -> str:
    try:
        content = part.get_content()  # type: ignore[attr-defined]
        if isinstance(content, str):
            return content[:MAX_TEXT_CHARS]
    except Exception:  # unknown charsets / broken encodings fall back below
        pass
    payload = part.get_payload(decode=True) or b""
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")[:MAX_TEXT_CHARS]
    except LookupError:
        return payload.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS]


def _walk(msg: Message, warnings: list[str]):
    """Yield (part, path) without descending into message/rfc822 parts."""
    stack: list[tuple[Message, str, int]] = [(msg, "0", 0)]
    while stack:
        part, path, depth = stack.pop()
        yield part, path
        if part.get_content_type() == "message/rfc822":
            continue
        if part.is_multipart():
            if depth >= MAX_DEPTH:
                warnings.append("mime_depth_limit_exceeded")
                continue
            payload = part.get_payload()
            if isinstance(payload, list):
                for i in range(len(payload) - 1, -1, -1):
                    stack.append((payload[i], f"{path}.{i}", depth + 1))


def _clean_url(candidate: str) -> str:
    return candidate.rstrip(_TRAILING_PUNCTUATION)


def _url_flags(parts: Any, link_text: str | None, shorteners: tuple[str, ...]) -> list[str]:
    flags: list[str] = []
    host_org = organizational_domain(parts.host) if parts.host_type == "domain" else None
    if link_text:
        for match in _DOMAIN_IN_TEXT_RE.finditer(link_text):
            try:
                text_domain = canonical_domain(match.group(1))
            except IndicatorError:
                continue
            if organizational_domain(text_domain) != host_org:
                flags.append("link_text_mismatch")
                break
    if parts.host_type == "ip":
        flags.append("ip_literal_host")
    elif has_punycode(parts.host):
        flags.append("punycode_host")
    if parts.has_userinfo:
        flags.append("embedded_credentials")
    if parts.host_type == "domain" and (parts.host in shorteners or host_org in shorteners):
        flags.append("url_shortener")
    if parts.port is not None:
        flags.append("nonstandard_port")
    return flags


# -- main entry points --------------------------------------------------------------------------


def parse_eml(raw: bytes, policy: Policy, *, max_parts: int = 200) -> ParsedEmail:
    parsed = ParsedEmail(message_sha256=sha256_hex(raw), size=len(raw))
    warnings = parsed.warnings
    try:
        msg = BytesParser(policy=email.policy.default).parsebytes(raw)
    except Exception as exc:  # defensive: the stdlib parser is lenient
        warnings.append(f"parser_exception:{type(exc).__name__}")
        parsed.partial = True
        return parsed

    from_values = _header_values(msg, "From", warnings)
    if not from_values:
        warnings.append("missing_from_header")
        parsed.partial = True
    elif len(from_values) > 1:
        warnings.append("multiple_from_headers")
    parsed.from_display, parsed.from_address = _parse_mailbox(
        from_values[0] if from_values else None, warnings, "From"
    )
    rp_values = _header_values(msg, "Return-Path", warnings)
    _, parsed.return_path = _parse_mailbox(rp_values[0] if rp_values else None, warnings, "Return-Path")
    rt_values = _header_values(msg, "Reply-To", warnings)
    _, parsed.reply_to = _parse_mailbox(rt_values[0] if rt_values else None, warnings, "Reply-To")
    for name, target in (("To", parsed.to), ("Cc", parsed.cc)):
        for _, address in email.utils.getaddresses(_header_values(msg, name, warnings)):
            try:
                target.append(canonical_email(address))
            except IndicatorError:
                if address:
                    warnings.append(f"invalid_address:{name}")

    subjects = _header_values(msg, "Subject", warnings)
    parsed.subject = subjects[0][:998] if subjects else None
    ids = _header_values(msg, "Message-ID", warnings)
    parsed.message_id = ids[0][:998] if ids else None
    if not parsed.message_id:
        warnings.append("missing_message_id")
    dates = _header_values(msg, "Date", warnings)
    if dates:
        try:
            parsed.date = iso(email.utils.parsedate_to_datetime(dates[0]))
        except (TypeError, ValueError, IndexError):
            warnings.append("unparseable_date")
    else:
        warnings.append("missing_date")

    from_domain = parsed.domain_of(parsed.from_address)
    parsed.authentication = interpret_authentication(
        _header_values(msg, "Authentication-Results", warnings), from_domain, policy
    )
    if parsed.authentication["trust"] == "assumed_topmost":
        warnings.append("auth_results_trust_assumed_topmost")
    elif parsed.authentication["trust"] == "untrusted":
        warnings.append("no_trusted_authentication_results")
    parsed.received = parse_received(_header_values(msg, "Received", warnings), policy)

    seen_urls: set[tuple[str, str]] = set()
    text_for_language: list[str] = [parsed.subject or ""]

    def record_url(candidate: str, source: str, location: str, link_text: str | None, defanged: bool) -> None:
        try:
            parts = canonical_url(candidate)
        except IndicatorError:
            warnings.append(f"unparseable_url:{location}")
            return
        key = (parts.normalized, source)
        if key in seen_urls:
            return
        seen_urls.add(key)
        flags = _url_flags(parts, link_text, policy.url_shorteners)
        if defanged:
            flags.append("defanged_in_source")
        parsed.urls.append(
            {
                "url": candidate[:2048],
                "normalized": parts.normalized,
                "host": parts.host,
                "host_display": domain_display(parts.host) if parts.host_type == "domain" else parts.host,
                "host_type": parts.host_type,
                "source": source,
                "location": location,
                "link_text": link_text or None,
                "flags": flags,
            }
        )

    def scan_text(text: str, source: str, location: str) -> None:
        for match in _URL_RE.finditer(text):
            record_url(_clean_url(match.group(0)), source, location, None, False)
        for match in _DEFANGED_URL_RE.finditer(text):
            refanged, _ = refang(_clean_url(match.group(0)))
            warnings.append(f"defanged_indicator_refanged:{location}")
            record_url(refanged, source, location, None, True)
        for match in _EMAIL_IN_TEXT_RE.finditer(text):
            address = match.group(0)
            if address.lower() not in parsed.body_emails:
                parsed.body_emails.append(address.lower())

    part_count = 0
    for part, path in _walk(msg, warnings):
        part_count += 1
        if part_count > max_parts:
            warnings.append("mime_part_limit_exceeded")
            parsed.partial = True
            break
        for defect in getattr(part, "defects", []):
            name = type(defect).__name__
            warnings.append(f"mime_defect:{name}")
            if name in SEVERE_DEFECTS:
                parsed.partial = True
        content_type = part.get_content_type()
        location = f"part:{path}"
        if content_type == "message/rfc822":
            inner = part.get_payload()
            try:
                data = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
            except Exception:
                data = b""
                warnings.append(f"nested_message_unreadable:{location}")
            record = analyze_attachment(
                _safe_filename(part.get_filename()) or "attached-message.eml",
                content_type, data, inline=False, location=location,
            )
            record["flags"].append("nested_message_not_parsed")
            parsed.attachments.append(record)
            continue
        if part.is_multipart():
            continue
        try:
            disposition = part.get_content_disposition()
            filename = part.get_filename()
        except Exception:
            disposition, filename = "attachment", None
            warnings.append(f"unreadable_disposition:{location}")
        if content_type in ("text/plain", "text/html") and disposition != "attachment" and not filename:
            text = _part_text(part)
            parsed.body_present = parsed.body_present or bool(text.strip())
            if content_type == "text/plain":
                text_for_language.append(text)
                scan_text(text, "text", location)
            else:
                extractor = _HtmlExtractor()
                try:
                    extractor.feed(text)
                    extractor.close()
                except Exception:
                    warnings.append(f"html_parse_error:{location}")
                visible = "".join(extractor.text)
                text_for_language.append(visible)
                for kind, target, link_text in extractor.links:
                    lowered = target.lower()
                    if lowered.startswith(("http://", "https://", "ftp://")):
                        record_url(target, kind, location, link_text, False)
                    elif lowered.startswith("mailto:"):
                        address = target[7:].split("?")[0]
                        if address and address.lower() not in parsed.body_emails:
                            parsed.body_emails.append(address.lower())
                scan_text(visible, "html_text", location)
                if extractor.data_urls:
                    warnings.append(f"data_url_present:{location}")
                if extractor.javascript_urls:
                    warnings.append(f"javascript_url_present:{location}")
            continue
        payload = part.get_payload(decode=True)
        data = payload if isinstance(payload, bytes) else b""
        parsed.attachments.append(
            analyze_attachment(
                _safe_filename(filename), content_type, data,
                inline=disposition == "inline", location=location,
            )
        )

    if not parsed.body_present and not parsed.attachments:
        warnings.append("no_body")
    language = " ".join(" ".join(text_for_language).lower().split())
    parsed.credential_phrases = [p for p in CREDENTIAL_PHRASES if p in language]
    return parsed


def normalize_email(
    raw: bytes,
    *,
    case_id: str,
    received_at: str,
    reporter: str | None,
    reported_at: str | None,
    raw_ref: dict[str, Any],
    settings: Settings,
) -> NormalizedCase:
    parsed = parse_eml(raw, settings.policy, max_parts=settings.max_mime_parts)
    collector = IndicatorCollector(
        settings.policy, lab_doc_ranges_routable=settings.lab_doc_ranges_routable
    )
    for header, address in (
        ("From", parsed.from_address),
        ("Return-Path", parsed.return_path),
        ("Reply-To", parsed.reply_to),
    ):
        if address:
            collector.add("email", address, origin="header", location=f"header:{header}")
            domain = parsed.domain_of(address)
            if domain:
                collector.add("domain", domain, origin="header", location=f"header:{header}")
    for hop in parsed.received:
        for ip in hop["ips"]:
            if not is_routable(ip, lab_doc_ranges_routable=settings.lab_doc_ranges_routable):
                continue
            collector.add(
                "ip", ip, origin="received",
                location=f"header:Received[{hop['index']}]:{hop['trust']}",
                scoring_eligible=hop["trust"] == "trusted_boundary",
            )
    for occurrence in parsed.urls:
        collector.add_url(
            occurrence["url"], origin="body",
            location=f"body:{occurrence['location']}:{occurrence['source']}",
        )
    for address in parsed.body_emails:
        collector.add("email", address, origin="body", location="body:email_address")
    for attachment in parsed.attachments:
        label = attachment["filename"] or attachment["location"]
        collector.add("sha256", attachment["sha256"], origin="attachment", location=f"attachment:{label}")

    def mailbox(address: str | None, display: str | None = None) -> dict[str, Any] | None:
        if not address:
            return None
        domain = parsed.domain_of(address)
        return {
            "address": address,
            "display_name": display,
            "domain": domain,
            "org_domain": organizational_domain(domain),
        }

    evidence = {
        "email": {
            "message_sha256": parsed.message_sha256,
            "size": parsed.size,
            "subject": parsed.subject,
            "from": mailbox(parsed.from_address, parsed.from_display),
            "return_path": mailbox(parsed.return_path),
            "reply_to": mailbox(parsed.reply_to),
            "to": parsed.to,
            "cc": parsed.cc,
            "message_id": parsed.message_id,
            "date": parsed.date,
            "authentication": parsed.authentication,
            "received": parsed.received,
            "urls": parsed.urls,
            "attachments": parsed.attachments,
            "credential_phrases": parsed.credential_phrases,
            "body_present": parsed.body_present,
        }
    }
    return NormalizedCase(
        case_id=case_id,
        source_type="email",
        source_event_id=f"sha256:{parsed.message_sha256}",
        received_at=received_at,
        observed_at=parsed.date,
        status="parse_partial" if parsed.partial else "normalized",
        entities={
            "reporter": reporter,
            "reported_at": reported_at,
            "user": parsed.to[0] if parsed.to else reporter,
            "agent": None,
            "sender": parsed.from_address,
        },
        indicators=collector.results(),
        evidence=evidence,
        parse_warnings=parsed.warnings + collector.warnings,
        dedupe_key=parsed.message_sha256,
        raw_ref=raw_ref,
    )
