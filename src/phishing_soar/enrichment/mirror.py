"""Convert a ThreatFox JSON export into the local IOC mirror format.

The refresh job (``scripts/refresh_ioc_mirror.py``) downloads the export on a
schedule, converts it here, and replaces the mirror atomically. A failed
refresh keeps the last-known-good file, so triage never depends on the
provider being reachable.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from typing import Any

from ..canonical import IndicatorError
from ..util import iso, parse_timestamp
from .local_ioc import canonicalize

TYPE_MAP = {"ip:port": "ip", "domain": "domain", "url": "url", "sha256_hash": "sha256"}


def _rows(export: Any) -> Iterator[dict[str, Any]]:
    """Accept both the ``{"<id>": [row, ...]}`` export shape and a plain list of rows."""
    if isinstance(export, dict):
        for value in export.values():
            if isinstance(value, list):
                yield from (row for row in value if isinstance(row, dict))
    elif isinstance(export, list):
        yield from (row for row in export if isinstance(row, dict))


def _provider_time(value: Any) -> datetime | None:
    """abuse.ch exports use ``YYYY-MM-DD HH:MM:SS`` (optionally suffixed ``UTC``)."""
    if not value:
        return None
    return parse_timestamp(str(value).replace(" UTC", "").strip().replace(" ", "T") + "Z")


def convert_threatfox_export(
    export: Any, *, now: datetime, ttl_days: int = 7, min_confidence: int = 50
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return (mirror entries, counters). Entries expire ``ttl_days`` after this refresh."""
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    counters = {"rows": 0, "kept": 0, "skipped_type": 0, "skipped_confidence": 0, "invalid": 0}
    expires = iso(now + timedelta(days=ttl_days))
    for row in _rows(export):
        counters["rows"] += 1
        raw_type = str(row.get("ioc_type", "")).lower()
        ioc_type = TYPE_MAP.get(raw_type)
        if ioc_type is None:
            counters["skipped_type"] += 1
            continue
        confidence = int(row.get("confidence_level") or 0)
        if confidence < min_confidence:
            counters["skipped_confidence"] += 1
            continue
        value = str(row.get("ioc_value") or row.get("ioc") or "").strip()
        if raw_type == "ip:port":
            value = value.rsplit(":", 1)[0].strip("[]")
        try:
            normalized = canonicalize(ioc_type, value)
        except IndicatorError:
            counters["invalid"] += 1
            continue
        tags = row.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        first_seen = _provider_time(row.get("first_seen_utc") or row.get("first_seen"))
        key = (ioc_type, normalized)
        current = entries.get(key)
        if current is None or confidence > current["confidence"]:
            entries[key] = {
                "type": ioc_type,
                "value": normalized,
                "verdict": "malicious",
                "confidence": confidence,
                "source": "threatfox-export",
                "first_seen": iso(first_seen) if first_seen else None,
                "expires_at": expires,
                "tags": sorted({str(t) for t in tags} | {str(row.get("malware_printable") or row.get("malware") or "")} - {""}),
            }
    counters["kept"] = len(entries)
    return sorted(entries.values(), key=lambda e: (e["type"], e["value"])), counters


def to_jsonl(entries: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries)
