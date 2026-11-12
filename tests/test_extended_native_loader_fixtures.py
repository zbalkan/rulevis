"""Regression guard for the expanded native differential fixture corpus.

These assertions check fixture integrity and coverage only. They are not
independent Wazuh runtime evidence; the pinned GDB workflow is the oracle.
"""
import json
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "wazuh_41410_differential.json"
ADDED = {
    "sid-multi-parent-history",
    "sid-partial-followup",
    "sid-repeated-with-history",
    "sid-overwrite-after-multi",
}


def test_extended_native_fixture_cases_are_distinct_and_ordered():
    suite = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert suite["schema_version"] == 1
    assert suite["wazuh_version"] == "4.14.10"
    cases = suite["scenarios"]
    identifiers = [case["id"] for case in cases]
    assert len(identifiers) == len(set(identifiers))
    assert ADDED <= set(identifiers)
    assert len(cases) >= 18
    for case in cases:
        assert case["rules"]
        assert all(type(rule["id"]) is int for rule in case["rules"])


def test_added_native_scenarios_preserve_targeted_interactions():
    cases = {
        case["id"]: case["rules"]
        for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["scenarios"]
    }
    multi = cases["sid-multi-parent-history"]
    assert any(r.get("if_sid") == "1,2" for r in multi)
    assert any(r.get("if_matched_sid") == 100101 for r in multi)
    partial = cases["sid-partial-followup"]
    assert any(r.get("if_sid") == "1,999999" for r in partial)
    assert any(r.get("if_sid") == "100101" for r in partial)
    repeated = cases["sid-repeated-with-history"]
    assert any(r.get("if_sid") == "1,1" for r in repeated)
    assert any(r.get("if_matched_group") == "audit" for r in repeated)
    overwrite = cases["sid-overwrite-after-multi"]
    assert any(r.get("overwrite") is True for r in overwrite)
    assert {r.get("if_matched_group") for r in overwrite} >= {"audit", "renamed"}
