import logging
import os
import sys

import pytest

import rulevis
from rulevis import CustomFileHandler, Rulevis


def test_validate_paths_accepts_directory(tmp_path):
    instance = object.__new__(Rulevis)

    instance._Rulevis__validate_paths([str(tmp_path)])


@pytest.mark.parametrize("paths", [[], ["/path/that/does/not/exist"]])
def test_validate_paths_rejects_invalid_input(paths):
    instance = object.__new__(Rulevis)

    with pytest.raises(SystemExit) as exc:
        instance._Rulevis__validate_paths(paths)

    assert exc.value.code == 1


def test_run_calls_pipeline_in_order(monkeypatch):
    instance = object.__new__(Rulevis)
    calls = []

    monkeypatch.setattr(
        instance,
        "_Rulevis__generate_graph",
        lambda: calls.append("graph"),
    )
    monkeypatch.setattr(
        instance,
        "_Rulevis__generate_stats",
        lambda: calls.append("stats"),
    )
    monkeypatch.setattr(
        instance,
        "_Rulevis__run_flask_app",
        lambda: calls.append("flask"),
    )

    instance.run()

    assert calls == ["graph", "stats", "flask"]


def test_temporary_files_are_cleaned_up(tmp_path):
    instance = Rulevis([str(tmp_path)])
    paths = [
        instance.graph_path,
        instance.stats_path,
        instance.heatmap_path,
    ]

    assert all(os.path.exists(path) for path in paths)

    instance.__del__()

    assert all(not os.path.exists(path) for path in paths)


def test_custom_file_handler_strips_ansi_sequences(tmp_path):
    log_path = tmp_path / "rulevis.log"
    handler = CustomFileHandler(str(log_path), encoding="utf-8")
    record = logging.LogRecord(
        name="source",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="\x1b[31mred\x1b[0m",
        args=(),
        exc_info=None,
    )

    try:
        handler.emit(record)
        handler.flush()
    finally:
        handler.close()

    assert record.name == "rulevis"
    assert log_path.read_text(encoding="utf-8").strip() == "red"


def test_main_parses_comma_separated_paths(monkeypatch):
    captured = {}

    class FakeRulevis:
        def __init__(self, paths):
            captured["paths"] = paths

        def run(self):
            captured["ran"] = True

    monkeypatch.setattr(rulevis, "Rulevis", FakeRulevis)
    monkeypatch.setattr(
        sys,
        "argv",
        ["rulevis", "--path", "/rules/one,/rules/two"],
    )

    rulevis.main()

    assert captured == {
        "paths": ["/rules/one", "/rules/two"],
        "ran": True,
    }


def test_main_accepts_ordered_rules_manifest(tmp_path, monkeypatch):
    manifest = tmp_path / "rules.txt"
    manifest.write_text("z-parent.xml\\na-child.xml\\n", encoding="utf-8")
    captured = {}

    class FakeRulevis:
        def __init__(self, paths, rule_files=None):
            captured["paths"] = paths
            captured["rule_files"] = rule_files

        def run(self):
            captured["ran"] = True

    monkeypatch.setattr(rulevis, "Rulevis", FakeRulevis)
    monkeypatch.setattr(sys, "argv", [
        "rulevis", "--path", str(tmp_path), "--rules-manifest", str(manifest)
    ])
    rulevis.main()

    assert captured["rule_files"] == [
        str(tmp_path / "z-parent.xml"),
        str(tmp_path / "a-child.xml"),
    ]
    assert captured["ran"] is True
