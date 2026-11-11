"""Safety and determinism tests for the native fixture preparer."""
from __future__ import annotations

from pathlib import Path
import pytest

from scripts.prepare_wazuh_41410_isolated import CONFIG, prepare


def test_preparer_replaces_only_fixture_in_marked_root(tmp_path: Path) -> None:
    runtime = tmp_path / "sandbox"
    runtime.mkdir()
    (runtime / ".rulevis-native-test-root").write_text(
        "Wazuh 4.14.10 disposable CI\n", encoding="utf-8"
    )
    fixture = tmp_path / "fixture.xml"
    fixture.write_text("<group name='audit'><rule id='100101' level='3'/></group>\n")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    prepare("sid-existing", fixture, evidence, runtime)
    assert (runtime / "etc/rules/rules.xml").read_bytes() == fixture.read_bytes()
    assert (evidence / "rules.xml").read_bytes() == fixture.read_bytes()
    assert (evidence / "ossec.conf").read_text() == CONFIG
    fixture.write_text("<group name='audit'><rule id='100102' level='3'/></group>\n")
    prepare("sid-forward", fixture, evidence, runtime)
    assert (runtime / "etc/rules/rules.xml").read_bytes() == fixture.read_bytes()


def test_preparer_refuses_unmarked_directory(tmp_path: Path) -> None:
    runtime = tmp_path / "sandbox"
    runtime.mkdir()
    fixture = tmp_path / "fixture.xml"
    fixture.write_text("<group/>")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(ValueError, match="unmarked"):
        prepare("sid-existing", fixture, evidence, runtime)
    assert not (runtime / "etc").exists()


def test_preparer_rejects_invalid_scenario_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid scenario"):
        prepare("../escape", tmp_path, tmp_path, tmp_path)
