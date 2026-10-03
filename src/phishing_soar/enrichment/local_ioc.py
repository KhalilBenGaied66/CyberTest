"""Versioned local IOC mirror (JSONL), consulted for every indicator on every run.

Each line: ``{"type", "value", "verdict", "confidence", "source", "first_seen",
"expires_at", "tags"}``. Expired entries are reported as ``stale`` and add no
reputation points. A malformed line is skipped with a load warning; it never
blocks the rest of the mirror.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..canonical import (
    IndicatorError,
    canonical_domain,
    canonical_email,
    canonical_ip,
    canonical_sha256,
    canonical_url,
)
from ..models import EnrichmentResult, Indicator
from ..util import iso, parse_timestamp

PROVIDER = "local_ioc"
SUPPORTED_TYPES = frozenset({"ip", "domain", "url", "sha256", "email"})
ALLOWED_VERDICTS = frozenset({"malicious", "suspicious"})


def canonicalize(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return canonical_ip(value)
    if ioc_type == "domain":
        return canonical_domain(value)
    if ioc_type == "url":
        return canonical_url(value).normalized
    if ioc_type == "sha256":
        return canonical_sha256(value)
    if ioc_type == "email":
        return canonical_email(value)
    raise IndicatorError(f"unsupported IOC type {ioc_type!r}")


class LocalIocIndex:
    def __init__(self, paths: tuple[Path, ...] | list[Path]) -> None:
        self.paths = tuple(Path(p) for p in paths)
        self.entries: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.load_warnings: list[str] = []
        self.loaded_files: list[str] = []
        self.newest_mtime: float | None = None
        self.reload()

    def reload(self) -> None:
        self.entries.clear()
        self.load_warnings.clear()
        self.loaded_files.clear()
        self.newest_mtime = None
        for path in self.paths:
            if not path.exists():
                self.load_warnings.append(f"ioc_file_missing:{path}")
                continue
            self.loaded_files.append(str(path))
            mtime = path.stat().st_mtime
            self.newest_mtime = mtime if self.newest_mtime is None else max(self.newest_mtime, mtime)
            with open(path, encoding="utf-8") as handle:
                for number, line in enumerate(handle, start=1):
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    self._load_line(path, number, line)

    def _load_line(self, path: Path, number: int, line: str) -> None:
        try:
            entry = json.loads(line)
            ioc_type = str(entry["type"]).lower()
            if ioc_type not in SUPPORTED_TYPES:
                raise ValueError(f"unsupported type {ioc_type}")
            verdict = str(entry.get("verdict", "malicious")).lower()
            if verdict not in ALLOWED_VERDICTS:
                raise ValueError(f"unsupported verdict {verdict}")
            normalized = canonicalize(ioc_type, str(entry["value"]))
        except (KeyError, ValueError, TypeError) as exc:
            self.load_warnings.append(f"ioc_line_rejected:{path.name}:{number}:{exc}")
            return
        record = {
            "type": ioc_type,
            "value": normalized,
            "verdict": verdict,
            "confidence": int(entry.get("confidence", 50)),
            "source": str(entry.get("source", path.name)),
            "first_seen": entry.get("first_seen"),
            "expires_at": entry.get("expires_at"),
            "tags": list(entry.get("tags") or []),
            "file": path.name,
            "line": number,
        }
        self.entries.setdefault((ioc_type, normalized), []).append(record)

    def feed_age_hours(self, now: datetime) -> float | None:
        if self.newest_mtime is None:
            return None
        return round(max(0.0, now.timestamp() - self.newest_mtime) / 3600, 1)

    def lookup(self, indicator: Indicator, now: datetime) -> EnrichmentResult:
        base = {
            "provider": PROVIDER,
            "indicator_id": indicator.indicator_id,
            "indicator_type": indicator.type,
            "indicator_value": indicator.normalized_value,
            "fetched_at": iso(now),
        }
        if indicator.type not in SUPPORTED_TYPES:
            return EnrichmentResult(status="not_applicable", match=None, verdict=None, **base)
        entries = self.entries.get((indicator.type, indicator.normalized_value), [])
        if not entries:
            return EnrichmentResult(status="ok", match=False, verdict="no_result", **base)
        active = []
        for entry in entries:
            expires = parse_timestamp(entry["expires_at"])
            if expires is None or expires > now:
                active.append(entry)
        if not active:
            newest = max(entries, key=lambda e: e["expires_at"] or "")
            return EnrichmentResult(
                status="ok", match=True, verdict="stale", confidence=newest["confidence"],
                details={"stale": True, "expired_at": newest["expires_at"], "source": newest["source"],
                         "tags": newest["tags"]},
                **base,
            )
        best = max(active, key=lambda e: (e["verdict"] == "malicious", e["confidence"]))
        return EnrichmentResult(
            status="ok", match=True, verdict=best["verdict"], confidence=best["confidence"],
            details={"source": best["source"], "tags": best["tags"], "first_seen": best["first_seen"],
                     "expires_at": best["expires_at"], "entry": f"{best['file']}:{best['line']}"},
            expires_at=best["expires_at"],
            **base,
        )
