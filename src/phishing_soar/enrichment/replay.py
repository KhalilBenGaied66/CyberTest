"""Replay transport: serves recorded provider responses from a manifest.

Used for deterministic demos and tests so expected scores never depend on what
public providers happen to know about inert lab indicators. It can also
simulate a total outage (``fail_with="timeout"``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .base import HttpRequest, HttpResponse, TransportError

_HOSTS = {
    "urlhaus-api.abuse.ch": "urlhaus",
    "threatfox-api.abuse.ch": "threatfox",
    "www.virustotal.com": "virustotal",
}


class ReplayTransport:
    def __init__(self, manifest_path: str | Path, *, fail_with: str | None = None) -> None:
        self.manifest_path = Path(manifest_path)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.defaults: dict[str, dict[str, Any]] = manifest["defaults"]
        self.responses: list[dict[str, Any]] = manifest["responses"]
        self.fail_with = fail_with
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: HttpRequest) -> HttpResponse:
        provider, key = self._identify(request)
        self.calls.append((provider, key))
        if self.fail_with:
            raise TransportError(self.fail_with, "replay: simulated outage")
        for entry in self.responses:
            if entry["provider"] == provider and entry["key"] == key:
                return self._respond(entry)
        return self._respond(self.defaults[provider])

    @staticmethod
    def _identify(request: HttpRequest) -> tuple[str, str]:
        parts = urlsplit(request.url)
        provider = _HOSTS.get(parts.hostname or "")
        if provider is None:
            raise TransportError("connection", f"replay: unknown host {parts.hostname}")
        if provider == "urlhaus":
            fields = parse_qs((request.body or b"").decode("ascii"))
            return provider, next(iter(fields.values()))[0] if fields else ""
        if provider == "threatfox":
            return provider, json.loads(request.body or b"{}").get("search_term", "")
        return provider, parts.path.split("/api/v3/", 1)[-1]

    def _respond(self, entry: dict[str, Any]) -> HttpResponse:
        body = b""
        if "file" in entry:
            body = (self.manifest_path.parent / entry["file"]).read_bytes()
        elif "body" in entry:
            body = json.dumps(entry["body"]).encode("utf-8")
        return HttpResponse(int(entry.get("status", 200)), dict(entry.get("headers", {})), body)
