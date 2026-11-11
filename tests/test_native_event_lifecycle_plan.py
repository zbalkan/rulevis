"""Validate the native event-lifecycle *plan*, not Wazuh runtime outcomes."""
from __future__ import annotations

import json
from pathlib import Path

PLAN = Path(__file__).parent / "fixtures" / "wazuh_41410_event_lifecycle.json"
REQUIRED = {
    "sid-insertion", "group-insertion", "dual-source-precedence",
    "group-multiplicity", "sid-search", "group-search",
    "timeframe-expiry", "agent-isolation", "match-level-suppression",
    "event-eviction-cleanup", "event-teardown-cleanup",
}


def test_native_event_history_plan_is_explicitly_unverified():
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    assert plan["schema_version"] == 1
    assert plan["wazuh_version"] == "4.14.10"
    assert plan["scope"] == "native_event_history_pending"
    assert {case["id"] for case in plan["cases"]} == REQUIRED
    assert len(plan["cases"]) == len(REQUIRED)
    for case in plan["cases"]:
        assert case["source"]
        assert len(case["steps"]) >= 2
        assert case["observe"]
        assert "expected" not in case
        assert "observed" not in case


def test_event_lifecycle_plan_never_masquerades_as_loader_oracle():
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    assert "provenance" not in plan
    assert "native_snapshot" not in plan
    assert all("native_result" not in case for case in plan["cases"])
