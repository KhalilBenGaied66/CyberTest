"""Minimal authenticated HTTP API that Shuffle workflows call (stdlib only).

Bind it to the lab network only. Every route except ``/healthz`` requires
``Authorization: Bearer $SOAR_API_TOKEN``; request bodies are size-limited
before they are read.

Routes:
  POST /v1/intake/email            message/rfc822 body (X-Reporter, X-Reported-At headers)
                                   or JSON {"eml_base64", "reporter", "reported_at", "labels"}
  POST /v1/intake/wazuh            Wazuh alert JSON (lab envelope or bare alert)
  POST /v1/cases/<id>/decision     {"token", "decision", "verdict", "reason", "analyst", ...}
  GET  /v1/cases/<id>              case snapshot (never contains approval tokens)
  POST /v1/actions/<id>/rollback   {"analyst", "reason"}
  POST /v1/jobs/approval-timeouts  scheduled every 5 minutes
  POST /v1/jobs/expire             scheduled every minute
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .approval import ApprovalError
from .audit import AuditWriteError
from .pipeline import IntakeError, PipelineError, SoarPipeline
from .response import ResponseError

_CASE_RE = re.compile(r"^/v1/cases/([0-9a-f-]{36})(/decision)?$")
_ROLLBACK_RE = re.compile(r"^/v1/actions/([A-Za-z0-9-]{1,64})/rollback$")
_JSON_LIMIT = 64 * 1024
_APPROVAL_STATUS = {"invalid_callback_token": 403, "no_pending_approval": 404}


class HttpError(Exception):
    def __init__(self, status: int, code: str, detail: str = "", **extra: Any) -> None:
        super().__init__(code)
        self.status = status
        self.payload = {"error": code, **({"detail": detail} if detail else {}), **extra}


def make_handler(pipeline: SoarPipeline, api_token: str) -> type[BaseHTTPRequestHandler]:
    expected = f"Bearer {api_token}".encode()
    settings = pipeline.settings

    class Handler(BaseHTTPRequestHandler):
        server_version = "phishing-soar/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # path only; tokens travel in bodies
            sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _require_auth(self) -> None:
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, expected):
                raise HttpError(401, "unauthorized")

        def _read_body(self, limit: int) -> bytes:
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                raise HttpError(411, "length_required")
            try:
                length = int(length_header)
            except ValueError as exc:
                raise HttpError(400, "invalid_content_length") from exc
            if length < 0:
                raise HttpError(400, "invalid_content_length")
            if length > limit:
                raise HttpError(413, "payload_too_large", f"limit {limit} bytes")
            return self.rfile.read(length)

        def _json_body(self, limit: int = _JSON_LIMIT) -> dict[str, Any]:
            raw = self._read_body(limit)
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HttpError(400, "invalid_json") from exc
            if not isinstance(data, dict):
                raise HttpError(400, "invalid_json", "expected an object")
            return data

        def _dispatch(self, method: str) -> None:
            try:
                if method == "GET" and self.path == "/healthz":
                    self._send(200, {"status": "ok"})
                    return
                self._require_auth()
                self._send(200, self._route(method))
            except HttpError as exc:
                self._send(exc.status, exc.payload)
            except IntakeError as exc:
                status = 413 if exc.code in ("too_large", "payload_too_large") else 400
                self._send(status, {"error": exc.code, "detail": exc.detail, "case_id": exc.case_id})
            except ApprovalError as exc:
                self._send(_APPROVAL_STATUS.get(exc.code, 409 if exc.code == "proposal_changed" else 400),
                           {"error": exc.code, "detail": str(exc)})
            except KeyError:
                self._send(404, {"error": "not_found"})
            except ResponseError as exc:
                self._send(409, {"error": "response_error", "detail": str(exc)})
            except PipelineError as exc:
                self._send(500, {"error": "pipeline_failed", "case_id": exc.case_id, "stage": exc.stage})
            except AuditWriteError:
                self._send(500, {"error": "audit_write_failed"})

        def _route(self, method: str) -> dict[str, Any]:
            path = self.path.split("?", 1)[0]
            if method == "POST" and path == "/v1/intake/email":
                return self._intake_email()
            if method == "POST" and path == "/v1/intake/wazuh":
                body = self._read_body(settings.max_wazuh_bytes)
                return pipeline.ingest_wazuh(body, execution_id=self.headers.get("X-Shuffle-Execution-Id"))
            match = _CASE_RE.match(path)
            if match and method == "GET" and not match.group(2):
                return pipeline.load_case(match.group(1))
            if match and method == "POST" and match.group(2):
                data = self._json_body()
                return pipeline.decide(match.group(1), str(data.pop("token", "")), data)
            match = _ROLLBACK_RE.match(path)
            if match and method == "POST":
                data = self._json_body()
                return pipeline.rollback(match.group(1), analyst=str(data.get("analyst", "")),
                                         reason=str(data.get("reason", "")))
            if method == "POST" and path == "/v1/jobs/approval-timeouts":
                return {"handled": pipeline.sweep_timeouts()}
            if method == "POST" and path == "/v1/jobs/expire":
                return {"handled": pipeline.run_expiry()}
            raise HttpError(404, "not_found")

        def _intake_email(self) -> dict[str, Any]:
            content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            execution_id = self.headers.get("X-Shuffle-Execution-Id")
            if content_type == "application/json":
                data = self._json_body(limit=settings.max_eml_bytes * 4 // 3 + _JSON_LIMIT)
                try:
                    raw = base64.b64decode(str(data.get("eml_base64", "")), validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise HttpError(400, "invalid_base64") from exc
                labels = data.get("labels") if isinstance(data.get("labels"), dict) else None
                return pipeline.ingest_email(raw, reporter=data.get("reporter"),
                                             reported_at=data.get("reported_at"),
                                             execution_id=execution_id or data.get("shuffle_execution_id"),
                                             labels=labels)
            # Content-Type is only a hint; the parser never trusts it for safety decisions.
            raw = self._read_body(settings.max_eml_bytes)
            return pipeline.ingest_email(raw, reporter=self.headers.get("X-Reporter"),
                                         reported_at=self.headers.get("X-Reported-At"),
                                         execution_id=execution_id)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

    return Handler


def build_server(pipeline: SoarPipeline, host: str, port: int) -> ThreadingHTTPServer:
    token = pipeline.settings.api_token
    if not token or len(token) < 24:
        raise SystemExit("SOAR_API_TOKEN must be set to a random value of at least 24 characters")
    return ThreadingHTTPServer((host, port), make_handler(pipeline, token))
