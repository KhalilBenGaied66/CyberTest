from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from phishing_soar.config import Policy, Settings
from phishing_soar.enrichment.replay import ReplayTransport
from phishing_soar.pipeline import SoarPipeline

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
MANIFEST = FIXTURES / "provider_responses" / "manifest.json"
NOW = datetime(2026, 10, 3, 7, 12, 0, tzinfo=timezone.utc)

P1_URL = "https://xn--prtal-example-i7k.test/login?session=8f2a"
P1_HOST = "xn--prtal-example-i7k.test"
P2_SHA256 = "13d3f0dc4aff277ab171d369e962c9cae1506d14de4aad97dde685f67d838bc9"
W1_IP = "198.51.100.44"


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def eml(name: str) -> bytes:
    return (FIXTURES / "eml" / name).read_bytes()


def wazuh_fixture(name: str) -> bytes:
    return (FIXTURES / "wazuh" / name).read_bytes()


def load_schema(name: str) -> dict:
    return json.loads((REPO / "schemas" / name).read_text(encoding="utf-8"))


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def policy() -> Policy:
    return Policy.from_file(REPO / "config" / "lab-policy.json")


@pytest.fixture
def settings(tmp_path: Path, policy: Policy) -> Settings:
    return Settings(
        data_dir=tmp_path / "runtime",
        ioc_paths=(FIXTURES / "local_iocs.jsonl",),
        policy=policy,
        lab_doc_ranges_routable=True,
        urlhaus_auth_key="test-urlhaus-key-0001",
        threatfox_auth_key="test-threatfox-key-0002",
        api_token="test-api-token-0123456789abcdef",
    )


@pytest.fixture
def replay() -> ReplayTransport:
    return ReplayTransport(MANIFEST)


@pytest.fixture
def make_pipeline(clock: Clock):
    def factory(settings: Settings, transport=None) -> SoarPipeline:
        return SoarPipeline(settings, transport=transport or ReplayTransport(MANIFEST), clock=clock,
                            sleep=lambda _: None)

    return factory


@pytest.fixture
def pipeline(settings: Settings, make_pipeline, replay: ReplayTransport) -> SoarPipeline:
    return make_pipeline(settings, replay)


def approve(pipeline: SoarPipeline, result: dict, *, analyst: str = "analyst-lab",
            reason: str = "Exact IOC match corroborated; approve bounded lab block", actions=None) -> dict:
    action_ids = [a["action_id"] for a in result["proposed_actions"]] if actions is None else actions
    return pipeline.decide(result["case_id"], result["approval"]["token"], {
        "decision": "approve", "verdict": "malicious", "reason": reason, "analyst": analyst,
        "approved_actions": action_ids,
    })


def reject(pipeline: SoarPipeline, result: dict, *, verdict: str = "benign",
           reason: str = "Legitimate vendor notification; sender platform expected") -> dict:
    return pipeline.decide(result["case_id"], result["approval"]["token"], {
        "decision": "reject", "verdict": verdict, "reason": reason, "analyst": "analyst-lab",
        "approved_actions": [],
    })
