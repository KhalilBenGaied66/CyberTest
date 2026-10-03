"""HTTP transport and the provider contract.

Providers only build requests and interpret responses; retries, timeouts,
caching, circuit breaking and quota live in :mod:`engine` so every provider
fails the same way. The transport never follows redirects and caps response
size.
"""

from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from ..models import Indicator

USER_AGENT = "phishing-soar-lab/0.1 (+reputation lookups only)"


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    connect_timeout: float = 5.0
    total_timeout: float = 10.0
    max_bytes: int = 1_000_000


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class TransportError(Exception):
    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind  # timeout | connection | too_large


Transport = Callable[[HttpRequest], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _read_limited(stream: Any, max_bytes: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise TransportError("timeout", "total timeout exceeded while reading")
        chunk = stream.read(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > max_bytes:
            raise TransportError("too_large", f"response exceeded {max_bytes} bytes")
        chunks.append(chunk)


def urllib_transport(request: HttpRequest) -> HttpResponse:
    """Default transport (stdlib). Honours HTTPS_PROXY via urllib's ProxyHandler."""
    req = urllib.request.Request(
        request.url, data=request.body, method=request.method,
        headers={"User-Agent": USER_AGENT, **request.headers},
    )
    deadline = time.monotonic() + request.total_timeout
    try:
        with _OPENER.open(req, timeout=request.connect_timeout) as resp:
            body = _read_limited(resp, request.max_bytes, deadline)
            return HttpResponse(resp.status, dict(resp.headers.items()), body)
    except urllib.error.HTTPError as exc:
        try:
            body = _read_limited(exc, request.max_bytes, deadline)
        except TransportError:
            body = b""
        return HttpResponse(exc.code, dict(exc.headers.items()) if exc.headers else {}, body)
    except TimeoutError as exc:
        raise TransportError("timeout", str(exc)) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise TransportError("timeout", str(exc.reason)) from exc
        raise TransportError("connection", str(exc.reason)) from exc
    except OSError as exc:
        raise TransportError("connection", str(exc)) from exc


def offline_transport(request: HttpRequest) -> HttpResponse:
    raise TransportError("connection", "network disabled")


@dataclass(frozen=True)
class Answer:
    """A provider's successful answer about one indicator."""

    match: bool
    verdict: str  # malicious | suspicious | no_result | no_detections
    confidence: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ProviderResponseError(ValueError):
    """The provider answered with something we cannot interpret."""


class Provider(ABC):
    name: str = ""
    supported_types: frozenset[str] = frozenset()
    no_result_on_404 = False

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def cache_ttl_seconds(self) -> int:
        return self.settings.cache_ttl_seconds

    @abstractmethod
    def missing_configuration(self) -> str | None:
        """Return a reason string when the provider cannot be used, else None."""

    @abstractmethod
    def build_request(self, indicator: Indicator) -> HttpRequest: ...

    @abstractmethod
    def interpret(self, indicator: Indicator, payload: Any) -> Answer: ...

    def request(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpRequest:
        return HttpRequest(
            method=method, url=url, headers=headers, body=body,
            connect_timeout=self.settings.connect_timeout,
            total_timeout=self.settings.total_timeout,
            max_bytes=self.settings.max_provider_response_bytes,
        )
