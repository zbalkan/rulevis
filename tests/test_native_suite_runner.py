"""Validated native-suite orchestration with simulated capture data only.

The tests never launch GDB or claim a compiled Wazuh result.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from internal.differential import predict
from scripts import run_wazuh_41410_suite as native_suite

FIXTURE = Path(__file__).parent / "fixtures" / "wazuh_41410_differential.json"


def _setup(tmp_path, monkeypatch, *, mismatch=False, invalid_rules=False):
    binary = tmp_path / "wazuh-analysisd"
    preparer = tmp_path / "prepare-fixture"
    binary.write_bytes(b"synthetic-only")
    preparer.write_text("synthetic-only", encoding="utf-8")
    workspace = tmp_path / "new-evidence"
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    names = {case["id"]: case for case in fixture["scenarios"]}
    calls = []

    def fake_prepare(argv, **kwargs):
        name, xml, evidence_dir = argv[1:]
        calls.append(("prepare", name))
        evidence = Path(evidence_dir)
        actual = Path(xml).read_bytes()
        (evidence / "rules.xml").write_bytes(
            b"<invalid/>" if invalid_rules else actual
        )
        (evidence / "ossec.conf").write_text(
            "<ossec_config><ruleset/></ossec_config>\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="prepared", stderr="")

    def fake_capture(**kwargs):
        name = kwargs["scenario_id"]
        calls.append(("capture", name))
        result = predict(names[name])
        if mismatch and name == "sid-existing":
            result["registrations"] = []
        kwargs["output"].write_text(json.dumps({
            "capture_format": "gdb_wazuh_41410_v2",
            "scenario_id": name,
            "loaded_rule_files": [{
                "path": str((kwargs["transcript"].parent.parent / "configs" / name / "rules.xml").resolve()),
                "sha256": __import__("hashlib").sha256(
                    (kwargs["transcript"].parent.parent / "configs" / name / "rules.xml").read_bytes()
                ).hexdigest(),
            }],
            "snapshot": {
                **result,
                "unexpected_rule_ids": [],
                "native_occurrence_count": 2,
            },
        }), encoding="utf-8")
        kwargs["transcript"].write_text("synthetic debugger output\n", encoding="utf-8")

    monkeypatch.setattr(native_suite.subprocess, "run", fake_prepare)
    monkeypatch.setattr(native_suite, "run_capture", fake_capture)
    return binary, preparer, workspace, fixture, calls


def test_orchestrator_runs_scenarios_sequentially_and_writes_reports(tmp_path, monkeypatch):
    binary, preparer, workspace, fixture, calls = _setup(tmp_path, monkeypatch)
    report = native_suite.run_suite(
        fixture=FIXTURE, binary=binary, preparer=preparer, workspace=workspace,
    )
    assert report["status"] == "match"
    assert calls == [
        step for item in fixture["scenarios"]
        for step in (("prepare", item["id"]), ("capture", item["id"]))
    ]
    assert (workspace / "native-oracle.json").is_file()
    assert (workspace / "differential-report.json").is_file()
    manifest = json.loads((workspace / "evidence-manifest.json").read_text(
        encoding="utf-8"
    ))
    assert manifest["basis"] == "native_capture_artifacts_not_runtime_attestation"
    assert "native-oracle.json" in manifest["files_sha256"]
    assert "differential-report.json" in manifest["files_sha256"]
    assert "captures/sid-existing.json" in manifest["files_sha256"]
    assert "transcripts/sid-existing.gdb.log" in manifest["files_sha256"]
    assert len(list((workspace / "transcripts").glob("*.prepare.log"))) == len(
        fixture["scenarios"]
    )
    with pytest.raises(ValueError, match="Refusing to reuse"):
        native_suite.run_suite(
            fixture=FIXTURE, binary=binary, preparer=preparer, workspace=workspace,
        )


def test_orchestrator_retains_divergences_without_claiming_matches(tmp_path, monkeypatch):
    binary, preparer, workspace, fixture, calls = _setup(
        tmp_path, monkeypatch, mismatch=True
    )
    report = native_suite.run_suite(
        fixture=FIXTURE, binary=binary, preparer=preparer, workspace=workspace,
    )
    assert report["status"] == "divergence"
    assert any(item["id"] == "sid-existing" and item["mismatches"]
               for item in report["results"])


def test_orchestrator_rejects_changed_deployed_rules_before_gdb(tmp_path, monkeypatch):
    binary, preparer, workspace, fixture, calls = _setup(
        tmp_path, monkeypatch, invalid_rules=True
    )
    with pytest.raises(ValueError, match="Prepared rules differ"):
        native_suite.run_suite(
            fixture=FIXTURE, binary=binary, preparer=preparer, workspace=workspace,
        )
    assert not any(step == "capture" for step, _ in calls)
    assert not (workspace / "native-oracle.json").exists()


def test_orchestrator_refuses_missing_manager_and_invalid_timeout(tmp_path, monkeypatch):
    binary, preparer, workspace, fixture, calls = _setup(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="must exist"):
        native_suite.run_suite(
            fixture=FIXTURE, binary=tmp_path / "missing",
            preparer=preparer, workspace=workspace,
        )
    with pytest.raises(ValueError, match="1..3600"):
        native_suite.run_suite(
            fixture=FIXTURE, binary=binary, preparer=preparer,
            workspace=workspace, timeout=0,
        )
    assert not workspace.exists()
