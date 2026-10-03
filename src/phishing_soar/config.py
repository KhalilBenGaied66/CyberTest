"""Runtime settings (environment) and lab policy (JSON file).

Secrets and modes come from environment variables; reviewable, non-secret
policy lists (allowlists, protected targets, trusted mail hosts) live in a JSON
policy file so they can be versioned and diffed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

MAX_BLOCK_TTL_SECONDS = 3600

DEFAULT_WAZUH_RULE_IDS = (
    "5712",  # sshd: brute force trying to get access to the system
    "5720",  # sshd: multiple authentication failures
    "5551",  # PAM: multiple failed logins
    "60204",  # Windows: multiple logon failures
    "100110",  # lab: authentication success after brute force (wazuh/custom-rules.xml)
    "100120",  # lab: source IP on local malicious-IP CDB list
)
DEFAULT_WAZUH_GROUPS = ("authentication_failures", "soar_lab")
DEFAULT_URL_SHORTENERS = (
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
)


@dataclass(frozen=True)
class Policy:
    """Non-secret lab policy. All values are compared case-insensitively."""

    internal_domains: tuple[str, ...] = ()
    protected_display_names: tuple[str, ...] = ()
    allowlist_domains: tuple[str, ...] = ()
    allowlist_networks: tuple[str, ...] = ()
    protected_networks: tuple[str, ...] = ()
    protected_domains: tuple[str, ...] = ()
    trusted_authserv_ids: tuple[str, ...] = ()
    trusted_mta_hosts: tuple[str, ...] = ()
    privileged_users: tuple[str, ...] = ("root", "admin", "administrator")
    service_account_prefixes: tuple[str, ...] = ("svc-", "svc_")
    critical_internet_facing_assets: tuple[str, ...] = ()
    watchlist_networks: tuple[str, ...] = ()
    wazuh_allowed_rule_ids: tuple[str, ...] = DEFAULT_WAZUH_RULE_IDS
    wazuh_allowed_groups: tuple[str, ...] = DEFAULT_WAZUH_GROUPS
    wazuh_success_after_failure_rule_ids: tuple[str, ...] = ("100110",)
    url_shorteners: tuple[str, ...] = DEFAULT_URL_SHORTENERS

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Policy:
        known = {f.name for f in fields(cls)}
        unknown = {k for k in data if not k.startswith("_")} - known
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        kwargs: dict[str, tuple[str, ...]] = {}
        for key, value in data.items():
            if key.startswith("_"):
                continue
            if not isinstance(value, (list, tuple)):
                raise ValueError(f"policy key {key!r} must be a list")
            kwargs[key] = tuple(str(item).strip().lower() for item in value if str(item).strip())
        return cls(**kwargs)

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        with open(path, encoding="utf-8") as handle:
            return cls.from_mapping(json.load(handle))


def _env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{key} must be a boolean, got {raw!r}")


def _env_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    return default if raw is None or raw.strip() == "" else int(raw)


def _env_float(env: Mapping[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    return default if raw is None or raw.strip() == "" else float(raw)


def _env_str(env: Mapping[str, str], key: str) -> str | None:
    raw = env.get(key)
    return raw.strip() if raw and raw.strip() else None


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("data/runtime")
    ioc_paths: tuple[Path, ...] = (Path("data/ioc/local_iocs.seed.jsonl"),)
    policy: Policy = field(default_factory=Policy)

    # Behaviour switches
    response_mode: str = "simulate"
    offline: bool = False
    lab_doc_ranges_routable: bool = False

    # Providers
    urlhaus_auth_key: str | None = None
    threatfox_auth_key: str | None = None
    vt_enabled: bool = False
    vt_api_key: str | None = None
    vt_per_minute: int = 3
    vt_per_day: int = 100
    connect_timeout: float = 5.0
    total_timeout: float = 10.0
    max_provider_response_bytes: int = 1_000_000
    cache_ttl_seconds: int = 6 * 3600
    vt_cache_ttl_seconds: int = 24 * 3600
    circuit_failure_threshold: int = 3
    circuit_window_seconds: int = 300
    circuit_open_seconds: int = 300

    # Workflow
    approval_timeout_seconds: int = 1800
    block_ttl_seconds: int = MAX_BLOCK_TTL_SECONDS
    dedupe_window_seconds: int = 86400

    # Intake limits
    max_eml_bytes: int = 10 * 1024 * 1024
    max_wazuh_bytes: int = 256 * 1024
    max_mime_parts: int = 200

    # Notifications
    notify_mode: str = "file"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    notify_from: str = "soar@lab.example"
    analyst_address: str = "analyst@lab.example"

    # Service
    api_token: str | None = None

    def __post_init__(self) -> None:
        if self.response_mode not in {"simulate"}:
            raise ValueError(
                "RESPONSE_MODE must be 'simulate' in this version; the Wazuh timed-block "
                "adapter is not implemented yet"
            )
        if not 0 < self.block_ttl_seconds <= MAX_BLOCK_TTL_SECONDS:
            raise ValueError(f"block TTL must be between 1 and {MAX_BLOCK_TTL_SECONDS} seconds")
        if self.notify_mode not in {"file", "smtp"}:
            raise ValueError("SOAR_NOTIFY_MODE must be 'file' or 'smtp'")
        if self.vt_per_minute < 1 or self.vt_per_day < 1:
            raise ValueError("VirusTotal budgets must be positive")

    def with_overrides(self, **changes: Any) -> Settings:
        return replace(self, **changes)

    def secret_values(self) -> tuple[str, ...]:
        """Values that must never appear in audit records or tickets."""
        candidates = (self.urlhaus_auth_key, self.threatfox_auth_key, self.vt_api_key, self.api_token)
        return tuple(value for value in candidates if value)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        policy_file = _env_str(env, "SOAR_POLICY_FILE")
        policy = Policy.from_file(policy_file) if policy_file else Policy()
        ioc_raw = _env_str(env, "SOAR_IOC_PATHS")
        ioc_paths = (
            tuple(Path(p.strip()) for p in ioc_raw.split(",") if p.strip())
            if ioc_raw
            else cls.ioc_paths
        )
        return cls(
            data_dir=Path(_env_str(env, "SOAR_DATA_DIR") or "data/runtime"),
            ioc_paths=ioc_paths,
            policy=policy,
            response_mode=(_env_str(env, "RESPONSE_MODE") or "simulate").lower(),
            offline=_env_bool(env, "SOAR_OFFLINE", False),
            lab_doc_ranges_routable=_env_bool(env, "SOAR_LAB_DOC_RANGES_ROUTABLE", False),
            urlhaus_auth_key=_env_str(env, "URLHAUS_AUTH_KEY"),
            threatfox_auth_key=_env_str(env, "THREATFOX_AUTH_KEY"),
            vt_enabled=_env_bool(env, "VT_ENABLED", False),
            vt_api_key=_env_str(env, "VT_API_KEY"),
            vt_per_minute=_env_int(env, "VT_PER_MINUTE", 3),
            vt_per_day=_env_int(env, "VT_PER_DAY", 100),
            connect_timeout=_env_float(env, "SOAR_CONNECT_TIMEOUT", 5.0),
            total_timeout=_env_float(env, "SOAR_TOTAL_TIMEOUT", 10.0),
            approval_timeout_seconds=_env_int(env, "SOAR_APPROVAL_TIMEOUT_SECONDS", 1800),
            block_ttl_seconds=_env_int(env, "SOAR_BLOCK_TTL_SECONDS", MAX_BLOCK_TTL_SECONDS),
            dedupe_window_seconds=_env_int(env, "SOAR_DEDUPE_WINDOW_SECONDS", 86400),
            notify_mode=(_env_str(env, "SOAR_NOTIFY_MODE") or "file").lower(),
            smtp_host=_env_str(env, "SOAR_SMTP_HOST") or "localhost",
            smtp_port=_env_int(env, "SOAR_SMTP_PORT", 1025),
            notify_from=_env_str(env, "SOAR_NOTIFY_FROM") or "soar@lab.example",
            analyst_address=_env_str(env, "SOAR_ANALYST_ADDRESS") or "analyst@lab.example",
            api_token=_env_str(env, "SOAR_API_TOKEN"),
        )
