"""Tested native artifact assembly with synthetic snapshots only.

Never treat these synthetic unit-test snapshots as evidence from analysisd.
"""
import hashlib
import json
from pathlib import Path

import pytest

from internal.differential import compare_suite, load_fixture, predict
from scripts.assemble_wazuh_41410_oracle import assemble
from scripts.render_wazuh_41410_rules import render_rules

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures" / "wazuh_41410_differential.json"
)


def _artifacts(tmp_path):
    fixture, digest = load_fixture(FIXTURE)
    captures = tmp_path / "captures"
    configs = tmp_path / "configs"
    captures.mkdir()
    configs.mkdir()
    binary = tmp_path / "analysisd"
    binary.write_bytes(b"synthetic-test-executable")
    for scenario in fixture["scenarios"]:
        sid = scenario["id"]
        (captures / (sid + ".json")).write_text(json.dumps({
            "capture_format": "gdb_wazuh_41410_v2",
            "scenario_id": sid,
            "loaded_rule_files": [{
                "path": str((configs / sid / "rules.xml").resolve()),
                "sha256": hashlib.sha256(
                    render_rules(scenario).encode("utf-8")
                ).hexdigest(),
            }],
            "snapshot": {
                **predict(scenario),
                "unexpected_rule_ids": [],
                "native_occurrence_count": 1,
            },
        }), encoding="utf-8")
        directory = configs / sid
        directory.mkdir()
        (directory / "rules.xml").write_text(render_rules(scenario), encoding="utf-8")
        (directory / "ossec.conf").write_text(
            "<ossec_config><ruleset><rule_include>rules.xml</rule_include>"
            "</ruleset></ossec_config>\n",
            encoding="utf-8",
        )
    return fixture, digest, captures, configs, binary


def test_assembler_builds_provenance_bound_schema(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    result = assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)
    assert result["provenance"]["fixture_sha256"] == digest
    assert result["provenance"]["binary_sha256"] == hashlib.sha256(
        binary.read_bytes()
    ).hexdigest()
    assert len(result["scenarios"]) == len(fixture["scenarios"])
    assert set(result["provenance"]["per_scenario_config_sha256"]) == {
        case["id"] for case in fixture["scenarios"]
    }
    # This is a contract check on synthetic data, not compiled-Wazuh validation.
    assert compare_suite(fixture, digest, result)["status"] == "match"


def test_assembler_rejects_missing_capture(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    (captures / (fixture["scenarios"][0]["id"] + ".json")).unlink()
    with pytest.raises(ValueError, match="Missing native GDB capture"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_mismatched_native_rules(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    xml = configs / fixture["scenarios"][0]["id"] / "rules.xml"
    xml.write_text("<group/>\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Rules XML differs"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_misidentified_scenario(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    file = captures / (fixture["scenarios"][0]["id"] + ".json")
    raw = json.loads(file.read_text(encoding="utf-8"))
    raw["scenario_id"] = "different"
    file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="scenario identity mismatch"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_unexpected_native_rule(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    file = captures / (fixture["scenarios"][0]["id"] + ".json")
    raw = json.loads(file.read_text(encoding="utf-8"))
    raw["snapshot"]["accepted_rules"].append("900000")
    file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected accepted rule IDs"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_nonisolated_manager_tree(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    file = captures / (fixture["scenarios"][0]["id"] + ".json")
    raw = json.loads(file.read_text(encoding="utf-8"))
    raw["snapshot"]["unexpected_rule_ids"] = ["999999"]
    file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="Unexpected rules loaded"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_loaded_rule_file_mismatch(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    name = fixture["scenarios"][0]["id"]
    file = captures / (name + ".json")
    raw = json.loads(file.read_text(encoding="utf-8"))
    raw["loaded_rule_files"][0]["sha256"] = "0" * 64
    file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="Loaded native rules do not match"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)


def test_assembler_rejects_multiple_native_rule_includes(tmp_path):
    fixture, digest, captures, configs, binary = _artifacts(tmp_path)
    name = fixture["scenarios"][0]["id"]
    file = captures / (name + ".json")
    raw = json.loads(file.read_text(encoding="utf-8"))
    raw["loaded_rule_files"].append(dict(raw["loaded_rule_files"][0]))
    file.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one observed rules file"):
        assemble(fixture=FIXTURE, captures=captures, configs=configs, binary=binary)
