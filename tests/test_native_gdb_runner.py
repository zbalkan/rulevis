"""Exercised the GDB wrapper without launching a native debugger."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_wazuh_41410_gdb as runner


FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures" / "wazuh_41410_differential.json"
)


def test_runner_exports_fixture_and_rejects_failed_native_probes(tmp_path, monkeypatch):
    binary = tmp_path / "wazuh-analysisd"
    binary.write_bytes(b"unit-test-executable")
    output = tmp_path / "sid-existing.json"

    def successful_run(command, **kwargs):
        env = kwargs["env"]
        assert command[:4] == ["gdb", "--batch", "--quiet", "--nx"]
        assert command[-2:] == [str(binary), "-t"]
        assert env["RULEVIS_NATIVE_SCENARIO_ID"] == "sid-existing"
        assert env["RULEVIS_NATIVE_SCENARIO"] == str(FIXTURE.resolve())
        output.write_text(json.dumps({
            "capture_format": "gdb_wazuh_41410_v2",
            "scenario_id": "sid-existing",
            "loaded_rule_files": [{"path": "/tmp/rules.xml", "sha256": "0" * 64}],
            "snapshot": {
                "accepted_rules": ["1"], "attachments": [], "registrations": [],
            },
        }), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(runner.subprocess, "run", successful_run)
    runner.run_capture(
        fixture=FIXTURE, scenario_id="sid-existing",
        binary=binary, output=output,
    )
    assert output.is_file()
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="sid-existing",
            binary=binary, output=output,
        )


def test_runner_rejects_missing_probe_output(tmp_path, monkeypatch):
    binary = tmp_path / "analysisd"
    binary.write_bytes(b"fixture")
    monkeypatch.setattr(
        runner.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stderr="", stdout="probe never hit",
        ),
    )
    with pytest.raises(RuntimeError, match="did not produce"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="sid-existing",
            binary=binary, output=tmp_path / "missing.json",
        )


def test_runner_rejects_wrong_scenario_capture(tmp_path, monkeypatch):
    binary = tmp_path / "analysisd"
    binary.write_bytes(b"fixture")
    output = tmp_path / "capture.json"

    def invalid_run(*args, **kwargs):
        output.write_text(json.dumps({
            "capture_format": "gdb_wazuh_41410_v1",
            "scenario_id": "other",
            "snapshot": {},
        }), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(runner.subprocess, "run", invalid_run)
    with pytest.raises(ValueError, match="Invalid native GDB snapshot"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="sid-existing",
            binary=binary, output=output,
        )
    assert not output.exists()


def test_runner_propagates_timeout_and_rejects_bad_input(tmp_path, monkeypatch):
    binary = tmp_path / "analysisd"
    binary.write_bytes(b"fixture")
    output = tmp_path / "capture.json"
    with pytest.raises(ValueError, match="Unknown scenario"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="invalid",
            binary=binary, output=output,
        )
    with pytest.raises(ValueError, match="positive"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="sid-existing",
            binary=binary, output=output, timeout=0,
        )

    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["gdb"], timeout=1)

    monkeypatch.setattr(runner.subprocess, "run", timed_out)
    with pytest.raises(RuntimeError, match="timed out"):
        runner.run_capture(
            fixture=FIXTURE, scenario_id="sid-existing",
            binary=binary, output=output,
        )
    assert not output.exists()
