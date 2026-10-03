"""Analyst/reporter notifications: local file outbox (default) or local SMTP (Mailpit).

Notifications contain defanged indicators only, never clickable live URLs,
never raw message bodies, and never approval tokens.
"""

from __future__ import annotations

import smtplib
import uuid
from collections.abc import Callable
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from .config import Settings
from .util import append_jsonl, iso, utcnow


class Notifier:
    channel = "base"

    def send(self, *, kind: str, case_id: str, recipients: list[str], subject: str, text: str) -> dict[str, Any]:
        raise NotImplementedError


class FileNotifier(Notifier):
    channel = "file"

    def __init__(self, outbox: Path, clock: Callable[[], datetime] = utcnow) -> None:
        self.outbox = Path(outbox)
        self.clock = clock
        self.fail = False  # fault injection for tests

    def send(self, *, kind: str, case_id: str, recipients: list[str], subject: str, text: str) -> dict[str, Any]:
        notification_id = "ntf-" + uuid.uuid4().hex[:12]
        if self.fail:
            return {"notification_id": notification_id, "channel": self.channel, "kind": kind,
                    "status": "failed", "error": "simulated notification failure", "recipients": recipients}
        append_jsonl(self.outbox, {"notification_id": notification_id, "sent_at": iso(self.clock()),
                                   "kind": kind, "case_id": case_id, "recipients": recipients,
                                   "subject": subject, "text": text})
        return {"notification_id": notification_id, "channel": self.channel, "kind": kind,
                "status": "sent", "recipients": recipients}


class SmtpNotifier(Notifier):
    channel = "smtp"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send(self, *, kind: str, case_id: str, recipients: list[str], subject: str, text: str) -> dict[str, Any]:
        notification_id = "ntf-" + uuid.uuid4().hex[:12]
        message = EmailMessage()
        message["From"] = self.settings.notify_from
        message["To"] = ", ".join(recipients)
        message["Subject"] = subject
        message["X-SOAR-Case"] = case_id
        message.set_content(text)
        try:
            with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=5) as smtp:
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            return {"notification_id": notification_id, "channel": self.channel, "kind": kind,
                    "status": "failed", "error": type(exc).__name__, "recipients": recipients}
        return {"notification_id": notification_id, "channel": self.channel, "kind": kind,
                "status": "sent", "recipients": recipients}


def build_notifier(settings: Settings, outbox: Path, clock: Callable[[], datetime]) -> Notifier:
    if settings.notify_mode == "smtp":
        return SmtpNotifier(settings)
    return FileNotifier(outbox, clock)
