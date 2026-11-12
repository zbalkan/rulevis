"""Checked the differential contract without claiming native Wazuh coverage."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from internal.differential import (
    compare_suite, load_fixture, normalize_snapshot, predict,
)

FIXTURE = Path(__file__).parent / "fixtures" / "wazuh_41410_differential.json"


def _oracle(suite, digest):
    # Synthetic data is used solely to test the comparison mechanism.
    # It is never committed as a compiled-Wazuh observation.
    return {
        "schema_version": 1,
        "provenance": {
            "engine": "compiled_wazuh_analysisd",
            "wazuh_version": "4.14.10",
            "fixture_sha256": digest,
            "binary_sha256": "0" * 64,
            "ruleset_config_sha256": "1" * 64,
            "capture_method": "synthetic test of comparison contract",
        },
        "scenarios": {
            case["id"]: predict(case) for case in suite["scenarios"]
        },
    }


def test_fixture_is_pinned_and_scenarios_have_unique_ids():
    suite, digest = load_fixture(FIXTURE)
    assert len(suite["scenarios"]) >= 9
    assert digest == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert len({case["id"] for case in suite["scenarios"]}) == len(suite["scenarios"])


def test_registration_fixtures_cover_forward_references_and_dual_history():
    suite, _ = load_fixture(FIXTURE)
    predictions = {case["id"]: predict(case) for case in suite["scenarios"]}
    def regs(name, relation):
        return [
            row for row in predictions[name]["registrations"]
            if row["relation_type"] == relation
        ]
    assert len(regs("sid-existing", "if_matched_sid")) == 1
    assert not regs("sid-forward", "if_matched_sid")
    assert len(regs("group-late", "if_matched_group")) == 1
    assert not regs("rejected-consumer", "if_matched_group")
    assert len(regs("dual-history", "if_matched_sid")) == 1
    assert len(regs("dual-history", "if_matched_group")) == 1
    assert len(regs("multiple-occurrences", "if_matched_group")) == 1
    assert regs("multiple-occurrences", "if_matched_group")[0]["count"] == 2
    assert regs("overwrite-missing", "if_matched_group") == [{
        "source_rule_id": "100101",
        "consumer_rule_id": "100201",
        "relation_type": "if_matched_group",
        "count": 1,
    }]
    assert not regs("shadowed-group", "if_matched_group")



def test_incremental_sid_scenarios_are_explicit_and_bounded():
    suite, _ = load_fixture(FIXTURE)
    cases = {scenario["id"]: scenario for scenario in suite["scenarios"]}
    assert len(cases) == 18

    self_attached = predict(cases["sid-sequential-self"])
    assert self_attached["accepted_rules"] == ["1", "100101"]
    assert self_attached["attachments"] == [
        {"parent_rule_id": "1", "child_rule_id": "100101", "relation_type": "if_sid", "count": 1},
        {"parent_rule_id": "100101", "child_rule_id": "100101", "relation_type": "if_sid", "count": 1},
    ]

    duplicates = predict(cases["sid-repeated-token"])
    assert duplicates["attachments"] == [
        {"parent_rule_id": "1", "child_rule_id": "100101", "relation_type": "if_sid", "count": 2},
    ]

    for scenario_id in ("sid-missing-then-existing", "sid-existing-then-missing"):
        snapshot = predict(cases[scenario_id])
        assert snapshot["attachments"] == [
            {"parent_rule_id": "1", "child_rule_id": "100101", "relation_type": "if_sid", "count": 1},
        ]


def test_comparison_reports_exact_model_vs_observed_differences():
    suite, digest = load_fixture(FIXTURE)
    oracle = _oracle(suite, digest)
    report = compare_suite(suite, digest, oracle)
    assert report["status"] == "match"
    assert all(row["status"] == "match" for row in report["results"])

    divergent = copy.deepcopy(oracle)
    divergent["scenarios"]["sid-existing"]["registrations"].clear()
    report = compare_suite(suite, digest, divergent)
    assert report["status"] == "divergence"
    assert [r["id"] for r in report["results"] if r["mismatches"]] == ["sid-existing"]
    mismatch = report["results"][0]["mismatches"]["registrations"]
    assert mismatch["modeled"] and mismatch["observed"] == []


@pytest.mark.parametrize("alteration", [
    lambda oracle: oracle["provenance"].update(engine="rulevis_model"),
    lambda oracle: oracle["provenance"].update(wazuh_version="4.14.12"),
    lambda oracle: oracle["provenance"].update(fixture_sha256="wrong"),
    lambda oracle: oracle["provenance"].pop("binary_sha256"),
    lambda oracle: oracle["provenance"].update(binary_sha256="not-a-sha256"),
    lambda oracle: oracle["scenarios"].pop("sid-existing"),
])
def test_native_oracle_provenance_and_coverage_are_mandatory(alteration):
    suite, digest = load_fixture(FIXTURE)
    oracle = _oracle(suite, digest)
    alteration(oracle)
    with pytest.raises(ValueError):
        compare_suite(suite, digest, oracle)


def test_snapshots_reject_duplicate_rows_and_boolean_occurrence_counts():
    snapshot = {
        "accepted_rules": ["1"],
        "attachments": [
            {"parent_rule_id": "1", "child_rule_id": "100101",
             "relation_type": "if_sid", "count": 1},
        ],
        "registrations": [],
    }
    assert normalize_snapshot(snapshot) == snapshot
    snapshot["attachments"][0]["count"] = True
    with pytest.raises(ValueError):
        normalize_snapshot(snapshot)
    snapshot["attachments"][0]["count"] = 1
    snapshot["attachments"].append(dict(snapshot["attachments"][0]))
    with pytest.raises(ValueError):
        normalize_snapshot(snapshot)


def test_bad_fixture_version_and_duplicate_scenarios_are_rejected(tmp_path):
    suite, _ = load_fixture(FIXTURE)
    suite["wazuh_version"] = "4.14.12"
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(suite), encoding="utf-8")
    with pytest.raises(ValueError):
        load_fixture(path)
    suite["wazuh_version"] = "4.14.10"
    suite["scenarios"].append(copy.deepcopy(suite["scenarios"][0]))
    path.write_text(json.dumps(suite), encoding="utf-8")
    with pytest.raises(ValueError):
        load_fixture(path)
