"""Transparent, versioned, deterministic risk scoring.

``score = min(100, sum(min(category points, category cap)))``. Every factor
carries the observed evidence, nominal points, the points actually applied
after the category cap, the cap, and its source, so the total recomputes
exactly. Unknown data adds zero points and is listed under ``unknowns``; it
never lowers risk and never means "clean".

The score prioritises; it does not decide. Containment is only ever
*proposed* here and always requires an analyst decision.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

from .canonical import canonical_url, defang, domain_matches, ip_in_networks
from .config import Settings
from .enrichment.engine import EnrichmentReport
from .models import Indicator, NormalizedCase
from .response.safety import UnsafeTargetError, check_block_target
from .util import sha256_hex

EXACT_SOURCES = ("local_ioc", "urlhaus", "threatfox")
MAX_CONTAINMENT_TARGETS = 3
DANGEROUS_ATTACHMENT_FLAGS = frozenset(
    {"executable", "script", "macro_office", "password_protected_archive"}
)
TYPE_MISMATCH_FLAGS = frozenset(
    {"mime_extension_mismatch", "magic_extension_mismatch", "double_extension"}
)
DECEPTIVE_LINK_FLAGS = frozenset(
    {"link_text_mismatch", "punycode_host", "ip_literal_host", "embedded_credentials"}
)
SHORTENER_FLAGS = frozenset({"url_shortener", "nonstandard_port"})
AUTH_UNKNOWN = frozenset({None, "none", "neutral", "temperror", "permerror", "policy"})


@lru_cache(maxsize=1)
def load_model_document() -> dict[str, Any]:
    text = resources.files("phishing_soar").joinpath("scoring_model.json").read_text("utf-8")
    return json.loads(text)


@dataclass
class ScoreResult:
    profile: str
    model_version: str
    total: int
    band: str
    categories: dict[str, dict[str, int]]
    factors: list[dict[str, Any]]
    observations: list[str]
    unknowns: list[dict[str, str]]
    recommended_verdict: str
    proposed_actions: list[dict[str, Any]]
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "band": self.band,
            "model_version": self.model_version,
            "factors": [
                {"id": f["factor_id"], "evidence": f["evidence"], "points": f["applied_points"],
                 "source": f["source"]}
                for f in self.factors
            ],
            "unknowns": self.unknowns,
            "flags": self.flags,
        }


def band_for(total: int, document: dict[str, Any] | None = None) -> str:
    document = document or load_model_document()
    for entry in document["bands"]:
        if entry["min"] <= total <= entry["max"]:
            return entry["band"]
    raise ValueError(f"score {total} outside defined bands")


def recompute_total(score: dict[str, Any]) -> int:
    """Independent recomputation from factors and caps (used by tests and auditors)."""
    by_category: dict[str, int] = {}
    caps: dict[str, int] = {}
    for factor in score["factors"]:
        by_category[factor["category"]] = by_category.get(factor["category"], 0) + factor["points"]
        caps[factor["category"]] = factor["cap"]
    return min(100, sum(min(points, caps[cat]) for cat, points in by_category.items()))


class _Builder:
    def __init__(self, model_version: str, model: dict[str, Any]) -> None:
        self.model_version = model_version
        self.model = model
        self.factors: list[dict[str, Any]] = []
        self.observations: list[str] = []
        self.unknowns: list[dict[str, str]] = []
        self.flags: list[str] = []

    def add(self, factor_id: str, evidence: str, source: str, indicator_id: str | None = None) -> None:
        spec = self.model["factors"][factor_id]
        self.factors.append(
            {
                "factor_id": factor_id,
                "category": spec["category"],
                "evidence": evidence,
                "points": spec["points"],
                "applied_points": 0,
                "cap": self.model["categories"][spec["category"]],
                "source": source,
                "indicator_id": indicator_id,
            }
        )

    def unknown(self, check: str, reason: str) -> None:
        self.unknowns.append({"check": check, "reason": reason})

    def finish(self, profile: str, document: dict[str, Any]) -> tuple[int, str, dict[str, dict[str, int]]]:
        categories = {
            name: {"cap": cap, "raw": 0, "applied": 0}
            for name, cap in self.model["categories"].items()
        }
        for factor in self.factors:
            category = categories[factor["category"]]
            category["raw"] += factor["points"]
            room = category["cap"] - category["applied"]
            factor["applied_points"] = max(0, min(factor["points"], room))
            category["applied"] += factor["applied_points"]
        total = min(100, sum(c["applied"] for c in categories.values()))
        return total, band_for(total, document), categories


def _reputation(case: NormalizedCase, report: EnrichmentReport, builder: _Builder) -> Indicator | None:
    model = builder.model
    threshold = model["vt_high_threshold"]
    candidates = []
    for indicator in case.indicators:
        if indicator.type not in model["reputation_types"] or not indicator.scoring_eligible:
            continue
        results = report.for_indicator(indicator.indicator_id)
        exact = sorted(
            {
                r.provider for r in results
                if r.status == "ok" and r.match and r.verdict == "malicious" and r.provider in EXACT_SOURCES
            }
        )
        vt = next((r for r in results if r.provider == "virustotal" and r.status == "ok"), None)
        vt_malicious = int(vt.details.get("malicious") or 0) if vt else 0
        agreeing = exact + (["virustotal"] if vt_malicious >= threshold else [])
        if exact:
            tier = 3
        elif vt_malicious >= threshold:
            tier = 2
        elif vt_malicious > 0 and "rep_vt_low" in model["factors"]:
            tier = 1
        else:
            continue
        candidates.append((tier, len(agreeing), indicator, exact, vt_malicious, agreeing))
    if not candidates:
        return None
    tier, _, indicator, exact, vt_malicious, agreeing = max(candidates, key=lambda c: (c[0], c[1]))
    label = f"{indicator.type} {indicator.safe_display}"
    if tier == 3:
        builder.add("rep_exact", f"{label} exact malicious match", ",".join(exact), indicator.indicator_id)
    elif tier == 2:
        builder.add("rep_vt_high", f"{label}: {vt_malicious} VirusTotal engines malicious", "virustotal",
                    indicator.indicator_id)
    else:
        builder.add("rep_vt_low", f"{label}: {vt_malicious} VirusTotal engines malicious", "virustotal",
                    indicator.indicator_id)
    if len(agreeing) >= 2:
        builder.add("rep_corrob", f"{len(agreeing)} independent sources agree on {label}",
                    ",".join(agreeing), indicator.indicator_id)
    return indicator if tier == 3 else None


def _email_factors(case: NormalizedCase, settings: Settings, builder: _Builder) -> None:
    ev = case.evidence["email"]
    policy = settings.policy

    auth = ev["authentication"]
    if auth["trust"] not in ("trusted", "assumed_topmost"):
        builder.unknown("authentication_results", auth["trust"])
    else:
        where = f"per {auth['authserv_id']}"
        if auth["dmarc"] == "fail":
            builder.add("auth_dmarc_fail", f"DMARC=fail {where}", "authentication-results")
        elif auth["dmarc"] in AUTH_UNKNOWN:
            builder.unknown("dmarc", auth["dmarc"] or "not_evaluated")
        if auth["spf"] == "fail":
            builder.add("auth_spf_fail", f"SPF=fail for {auth['spf_domain']} {where}", "authentication-results")
        elif auth["spf"] == "softfail":
            builder.add("auth_spf_softfail", f"SPF=softfail for {auth['spf_domain']} {where}",
                        "authentication-results")
        elif auth["spf"] in AUTH_UNKNOWN:
            builder.unknown("spf", auth["spf"] or "not_evaluated")
        if auth["dkim"] == "fail":
            builder.add("auth_dkim_fail", f"DKIM=fail {where}", "authentication-results")
        elif auth["dkim"] == "pass_unaligned":
            builder.observations.append("DKIM passes for a domain not aligned with From (0 points)")
        elif auth["dkim"] in (None, "none"):
            builder.observations.append("No usable DKIM signature (0 points; common)")
        if auth["spf"] == "pass" and auth["dkim"] == "pass_aligned" and auth["dmarc"] == "pass":
            builder.observations.append("SPF, aligned DKIM and DMARC pass: authenticated sender, not proof of benign content")

    sender = ev.get("from")
    if not sender:
        builder.unknown("sender_identity", "missing_from")
    else:
        from_org = sender["org_domain"]
        return_path = ev.get("return_path")
        if return_path and return_path["org_domain"] and return_path["org_domain"] != from_org:
            builder.add("id_return_path_mismatch",
                        f"From org domain {from_org} != Return-Path {return_path['org_domain']}", "headers")
        reply_to = ev.get("reply_to")
        if reply_to and reply_to["org_domain"] and reply_to["org_domain"] != from_org:
            builder.add("id_reply_to_mismatch",
                        f"Reply-To org domain {reply_to['org_domain']} != From {from_org}", "headers")
        display = (sender.get("display_name") or "").lower()
        trusted_sender = sender["domain"] and domain_matches(
            sender["domain"], policy.internal_domains + policy.allowlist_domains
        )
        for name in policy.protected_display_names:
            if name and name in display and not trusted_sender:
                builder.add("id_display_name_impersonation",
                            f"Display name '{sender['display_name']}' from unrelated domain {sender['domain']}",
                            "headers")
                break

    attachments = ev["attachments"]
    dangerous = [a for a in attachments if DANGEROUS_ATTACHMENT_FLAGS & set(a["flags"])]
    if dangerous:
        a = dangerous[0]
        kinds = sorted(DANGEROUS_ATTACHMENT_FLAGS & set(a["flags"]))
        builder.add("content_dangerous_attachment", f"{a['filename']} ({', '.join(kinds)})", "mime")
    mismatched = [a for a in attachments if TYPE_MISMATCH_FLAGS & set(a["flags"])]
    if mismatched:
        a = mismatched[0]
        kinds = sorted(TYPE_MISMATCH_FLAGS & set(a["flags"]))
        builder.add("content_attachment_type_mismatch",
                    f"{a['filename']} declared {a['declared_mime']} ({', '.join(kinds)})", "mime")
    urls = ev["urls"]
    deceptive = [u for u in urls if DECEPTIVE_LINK_FLAGS & set(u["flags"])]
    if deceptive:
        u = max(deceptive, key=lambda item: len(DECEPTIVE_LINK_FLAGS & set(item["flags"])))
        kinds = sorted(DECEPTIVE_LINK_FLAGS & set(u["flags"]))
        shown = f" shown as '{u['link_text']}'" if u.get("link_text") else ""
        builder.add("content_deceptive_link", f"{defang(u['normalized'])}{shown} ({', '.join(kinds)})", "body")
    web_links = [u for u in urls if u["normalized"].startswith(("http://", "https://"))]
    if ev["credential_phrases"] and web_links:
        builder.add("content_credential_lure",
                    f"credential language {ev['credential_phrases'][:3]} with {len(web_links)} web link(s)",
                    "body")
    shortened = [u for u in urls if SHORTENER_FLAGS & set(u["flags"])]
    if shortened:
        u = shortened[0]
        builder.add("content_shortener_or_port",
                    f"{defang(u['normalized'])} ({', '.join(sorted(SHORTENER_FLAGS & set(u['flags'])))})",
                    "body")
    if case.status == "parse_partial":
        builder.flags.append("parse_partial")
        builder.unknown("message_parsing", "partial; manual review required")


def _wazuh_factors(case: NormalizedCase, settings: Settings, builder: _Builder) -> None:
    ev = case.evidence["wazuh"]
    policy = settings.policy
    thresholds = builder.model["thresholds"]
    behavior = ev["behavior"]
    failures = behavior["authentication_failures_5m"]
    users = behavior["distinct_users_5m"]
    success = behavior["success_after_failures"]
    source = f"wazuh rule {ev['rule']['id']}"
    if failures is not None and failures >= thresholds["failures_5m"]:
        builder.add("auth_fail_burst", f"{failures} failures from one IP in 5m", source)
    if users is not None and users >= thresholds["distinct_users_5m"]:
        builder.add("multi_user", f"{users} distinct usernames targeted in 5m", source)
    if success:
        builder.add("success_after_fail", "successful login followed failures from the same IP", source)
    if failures is None and users is None and success is None:
        level = ev["rule"]["level"]
        if level is not None and level >= thresholds["high_level"]:
            builder.add("high_severity_no_counts", f"Wazuh level {level}; detailed counts unavailable", source)
        builder.unknown("behavior_counts", "unavailable")
    else:
        if failures is None:
            builder.unknown("authentication_failures_5m", "unavailable")
        if users is None:
            builder.unknown("distinct_users_5m", "unavailable")
    if behavior.get("counts_source") == "previous_output":
        builder.observations.append("Behavior counts derived from Wazuh previous_output")

    user = (ev.get("user") or "").lower()
    if user and (user in policy.privileged_users or user.startswith(policy.service_account_prefixes)):
        builder.add("privileged_user", f"privileged/service account targeted: {ev['user']}", source)
    agent_name = (ev["agent"].get("name") or "").lower()
    if agent_name and agent_name in policy.critical_internet_facing_assets:
        builder.add("critical_asset", f"internet-facing critical asset {ev['agent']['name']}", "lab policy")
    srcip = next((i for i in case.indicators if i.type == "ip"), None)
    if srcip and ip_in_networks(srcip.normalized_value, policy.watchlist_networks):
        builder.add("watchlist_source", f"{srcip.safe_display} on local watchlist", "lab policy")


def _propose_containment(
    case: NormalizedCase,
    band: str,
    exact_indicator: Indicator | None,
    exact_indicators: list[Indicator],
    settings: Settings,
    builder: _Builder,
) -> list[dict[str, Any]]:
    if band == "low":
        return []
    candidates: list[tuple[str, str, str]] = []  # (target_type, target, justification)
    if case.source_type == "wazuh":
        srcip = next((i for i in case.indicators if i.type == "ip"), None)
        if srcip and (band == "high" or exact_indicator is not None):
            candidates.append(("ip", srcip.normalized_value, f"source of {case.evidence['wazuh']['rule']['description']}"))
        scope = f"agent:{(case.entities.get('agent') or {}).get('name') or 'unknown'}"
    else:
        for indicator in exact_indicators:
            if indicator.type in ("ip", "domain"):
                candidates.append((indicator.type, indicator.normalized_value, f"exact malicious {indicator.type}"))
            elif indicator.type == "url":
                host = canonical_url(indicator.normalized_value)
                candidates.append(
                    (host.host_type, host.host, f"host of exact malicious URL {indicator.safe_display}")
                )
        scope = "lab-egress-blocklist"
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for target_type, target, justification in candidates:
        if (target_type, target) in seen or len(actions) >= MAX_CONTAINMENT_TARGETS:
            continue
        seen.add((target_type, target))
        try:
            canonical = check_block_target(
                target_type, target, settings.policy, lab_doc_ranges_routable=settings.lab_doc_ranges_routable
            )
        except UnsafeTargetError as exc:
            builder.flags.append(f"containment_suppressed:{exc.reason}:{defang(target)}")
            if exc.reason == "allowlisted":
                builder.flags.append("allowlist_conflict")
            continue
        action_type = "temporary_ip_block" if target_type == "ip" else "temporary_domain_block"
        actions.append(
            {
                "action_id": "act-" + sha256_hex(f"{case.case_id}|{action_type}|{canonical}|{scope}")[:12],
                "type": action_type,
                "target": canonical,
                "target_display": defang(canonical),
                "scope": scope,
                "ttl_seconds": settings.block_ttl_seconds,
                "adapter": "simulated_blocklist",
                "mode": settings.response_mode,
                "rollback": "automatic expiry after TTL; manual rollback by rollback_id",
                "justification": justification,
                "requires_approval": True,
            }
        )
    return actions


def score_case(case: NormalizedCase, report: EnrichmentReport, settings: Settings) -> ScoreResult:
    document = load_model_document()
    model_version = "email-1.0" if case.source_type == "email" else "wazuh-1.0"
    model = document["models"][model_version]
    builder = _Builder(model_version, model)

    exact_indicator = _reputation(case, report, builder)
    if case.source_type == "email":
        _email_factors(case, settings, builder)
    else:
        _wazuh_factors(case, settings, builder)

    for provider, reasons in sorted(report.provider_reasons.items()):
        builder.unknown(provider, ",".join(reasons))
    if report.completeness != "complete":
        builder.observations.append(
            f"Enrichment {report.completeness} ({report.enrichment_mode}); unknown results add 0 points"
        )

    exact_indicators = []
    for indicator in case.indicators:
        results = report.for_indicator(indicator.indicator_id)
        malicious = any(
            r.status == "ok" and r.match and r.verdict == "malicious" and r.provider in EXACT_SOURCES
            for r in results
        )
        if malicious and indicator.scoring_eligible:
            exact_indicators.append(indicator)
            if indicator.allowlisted:
                builder.flags.append("allowlist_conflict")

    total, band, categories = builder.finish(model["profile"], document)
    proposed = _propose_containment(case, band, exact_indicator, exact_indicators, settings, builder)
    verdict = {"high": "malicious", "medium": "suspicious", "low": "likely_benign"}[band]
    return ScoreResult(
        profile=model["profile"],
        model_version=model_version,
        total=total,
        band=band,
        categories=categories,
        factors=builder.factors,
        observations=builder.observations,
        unknowns=builder.unknowns,
        recommended_verdict=verdict,
        proposed_actions=proposed,
        flags=sorted(set(builder.flags)),
    )
