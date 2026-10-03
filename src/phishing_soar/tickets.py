"""Human-readable analyst card and local Markdown/JSON tickets.

Everything rendered here is derived from the case snapshot and contains only
defanged indicators. Approval tokens never appear in tickets or cards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import write_json_atomic, write_text_atomic

TOP_FACTORS = 5


def _factor_rows(score: dict[str, Any], limit: int | None = None) -> list[str]:
    factors = sorted(score["factors"], key=lambda f: -f["applied_points"])
    if limit:
        factors = factors[:limit]
    return [
        f"| {f['factor_id']} | {f['category']} | {f['evidence']} | {f['applied_points']}/{f['points']} | {f['source']} |"
        for f in factors
    ]


def render_card(snapshot: dict[str, Any]) -> str:
    """The analyst notification card: evidence first, then the proposed bounded action."""
    case = snapshot["case"]
    score = snapshot["score"]
    enrichment = snapshot["enrichment"]
    lines = [
        f"Case {case['case_id']} [{case['source_type']}]",
        f"Score {score['total']} {score['band'].upper()} (model {score['model_version']}); "
        f"enrichment {enrichment['completeness']} / {enrichment['enrichment_mode']}",
        f"Received {case['received_at']}; observed {case['observed_at'] or 'unknown'}",
    ]
    if case["source_type"] == "email":
        email = case["evidence"]["email"]
        sender = (email.get("from") or {}).get("address") or "unknown"
        lines.append(f"Subject: {email.get('subject') or '(none)'}")
        lines.append(f"From: {sender.replace('.', '[.]').replace('@', '[@]')}")
    else:
        wazuh = case["evidence"]["wazuh"]
        lines.append(f"Wazuh rule {wazuh['rule']['id']} (level {wazuh['rule']['level']}): {wazuh['rule']['description']}")
        lines.append(f"Agent: {wazuh['agent'].get('name')}; user: {wazuh.get('user')}")
    lines.append("")
    lines.append("Top factors:")
    for factor in sorted(score["factors"], key=lambda f: -f["applied_points"])[:TOP_FACTORS]:
        lines.append(f"  +{factor['applied_points']:>2} {factor['factor_id']}: {factor['evidence']} [{factor['source']}]")
    if score["unknowns"]:
        lines.append("Unknowns (0 points, not clean):")
        for unknown in score["unknowns"]:
            lines.append(f"  ? {unknown['check']}: {unknown['reason']}")
    if score["flags"]:
        lines.append(f"Flags: {', '.join(score['flags'])}")
    lines.append("")
    if score["proposed_actions"]:
        lines.append("Proposed containment (requires approval):")
        for action in score["proposed_actions"]:
            lines.append(
                f"  {action['action_id']}: {action['type']} {action['target_display']} scope={action['scope']} "
                f"ttl={action['ttl_seconds']}s mode={action['mode']} rollback={action['rollback']}"
            )
    else:
        lines.append("No containment proposed. Ticket and notification only.")
    lines.append(f"Recommendation: {score['recommended_verdict']} (analyst decides)")
    approval = snapshot.get("approval") or {}
    if approval:
        lines.append(f"Decision required before {approval.get('expires_at')}: approve (verdict=malicious) or reject.")
    lines.append(f"Ticket: {snapshot.get('ticket_path')}")
    return "\n".join(lines)


def render_ticket(snapshot: dict[str, Any]) -> str:
    case = snapshot["case"]
    score = snapshot.get("score")
    enrichment = snapshot.get("enrichment")
    out = [
        f"# Case {case['case_id']}",
        "",
        f"- **Source:** {case['source_type']} (`{case['source_event_id']}`)",
        f"- **Status:** {snapshot['status']}" + (f" / outcome `{snapshot['outcome']}`" if snapshot.get("outcome") else ""),
        f"- **Received:** {case['received_at']}; **observed:** {case['observed_at'] or 'unknown'}",
        f"- **Raw artifact SHA-256:** `{case['raw_ref'].get('sha256')}`",
    ]
    if score:
        out.append(f"- **Score:** {score['total']} {score['band'].upper()} (model `{score['model_version']}`)")
    if enrichment:
        out.append(f"- **Enrichment:** {enrichment['completeness']} / {enrichment['enrichment_mode']}")
    out += ["", "## Analyst card", "", "```text", snapshot.get("card", "(pending)"), "```", ""]
    if score:
        out += ["## Score explanation", "", "| Factor | Category | Evidence | Applied/Nominal | Source |",
                "|---|---|---|---|---|", *_factor_rows(score), ""]
        out.append("Category subtotals: " + ", ".join(
            f"{name} {c['applied']}/{c['cap']}" for name, c in score["categories"].items()))
        out.append("")
        if score["observations"]:
            out += ["Observations (0 points):", *[f"- {o}" for o in score["observations"]], ""]
    out += ["## Indicators (defanged)", "", "| Type | Value | First seen in | Scope |", "|---|---|---|---|"]
    for indicator in case["indicators"]:
        out.append(
            f"| {indicator['type']} | `{indicator['safe_display']}` | {indicator['first_seen_in']} | {indicator['scope']} |"
        )
    out.append("")
    if case["parse_warnings"]:
        out += ["## Parse warnings", "", *[f"- `{w}`" for w in case["parse_warnings"]], ""]
    decision = snapshot.get("decision")
    if decision:
        out += ["## Decision", "",
                f"- **{decision.get('approval')}** by `{decision.get('analyst', 'system')}` at {decision.get('decided_at')}",
                f"- Verdict: `{decision.get('verdict')}`", f"- Reason: {decision.get('reason')}", ""]
    if snapshot.get("actions"):
        out += ["## Actions", "", "| Action | Type | Target | Scope | Result | Expires | Rollback ID |",
                "|---|---|---|---|---|---|---|"]
        for action in snapshot["actions"]:
            out.append(
                f"| {action['action_id']} | {action['type']} | `{action['target'].replace('.', '[.]')}` | {action['scope']} "
                f"| {action['result']} | {action.get('expires_at')} | {action['rollback_id']} |"
            )
        out.append("")
    if snapshot.get("rollbacks"):
        out += ["## Rollbacks", "", *[
            f"- {r['action_id']} removed at {r.get('removed_at')} ({r.get('removal_reason')}): {r['result']}"
            for r in snapshot["rollbacks"]], ""]
    out += ["## Timeline", "", *[f"- {h['at']} — {h['status']}" for h in snapshot["status_history"]], ""]
    if snapshot.get("duplicates"):
        out += ["## Duplicate submissions", "", *[
            f"- {d['received_at']} (`{d['ingest_sha256'][:16]}…`)" for d in snapshot["duplicates"]], ""]
    return "\n".join(out)


class TicketWriter:
    def __init__(self, tickets_dir: Path) -> None:
        self.tickets_dir = Path(tickets_dir)

    def path_for(self, case_id: str) -> Path:
        return self.tickets_dir / f"{case_id}.md"

    def write(self, snapshot: dict[str, Any]) -> Path:
        case_id = snapshot["case"]["case_id"]
        path = self.path_for(case_id)
        write_text_atomic(path, render_ticket(snapshot))
        score = snapshot.get("score") or {}
        write_json_atomic(
            self.tickets_dir / f"{case_id}.json",
            {
                "case_id": case_id,
                "status": snapshot["status"],
                "outcome": snapshot.get("outcome"),
                "score": score.get("total"),
                "band": score.get("band"),
                "decision": (snapshot.get("decision") or {}).get("approval"),
                "verdict": (snapshot.get("decision") or {}).get("verdict"),
                "actions": [
                    {"action_id": a["action_id"], "result": a["result"], "rollback_id": a["rollback_id"]}
                    for a in snapshot.get("actions", [])
                ],
                "updated_at": snapshot["status_history"][-1]["at"],
            },
        )
        return path
