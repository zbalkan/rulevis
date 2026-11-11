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

        def close(self):
            captured["closed"] = True

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
        "closed": True,
    }


def test_main_cleans_up_when_flask_returns_normally(monkeypatch, tmp_path):
    instances = []

    class FakeRulevis:
        def __init__(self, paths):
            self.paths = paths
            self.closed = False
            instances.append(self)

        def run(self):
            pass

        def close(self):
            self.closed = True

    monkeypatch.setattr(rulevis, "Rulevis", FakeRulevis)
    monkeypatch.setattr(sys, "argv", ["rulevis", "--path", str(tmp_path)])
    rulevis.main()
    assert len(instances) == 1
    assert instances[0].closed


def test_main_cleans_up_when_interrupted(monkeypatch, tmp_path):
    instances = []

    class FakeRulevis:
        def __init__(self, paths):
            self.closed = False
            instances.append(self)

        def run(self):
            raise KeyboardInterrupt

        def close(self):
            self.closed = True

    monkeypatch.setattr(rulevis, "Rulevis", FakeRulevis)
    monkeypatch.setattr(sys, "argv", ["rulevis", "--path", str(tmp_path)])
    with pytest.raises(KeyboardInterrupt):
        rulevis.main()
    assert instances[0].closed


def test_cli_returns_130_for_keyboard_interrupt(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(rulevis, "_get_log_path", lambda: str(tmp_path / "run.log"))

    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(rulevis, "main", interrupt)
    assert rulevis.cli() == 130
    assert "Cancelled by user." in capsys.readouterr().out


def test_cli_returns_zero_after_clean_server_shutdown(monkeypatch, tmp_path):
    monkeypatch.setattr(rulevis, "_get_log_path", lambda: str(tmp_path / "run.log"))
    monkeypatch.setattr(rulevis, "main", lambda: None)
    assert rulevis.cli() == 0


def test_browser_launch_thread_does_not_block_exit(monkeypatch, tmp_path):
    instance = Rulevis([str(tmp_path)])
    timers = []
    runs = []

    class FakeTimer:
        def __init__(self, delay, callback):
            self.delay = delay
            self.callback = callback
            self.daemon = False
            timers.append(self)

        def start(self):
            runs.append("timer")

    class FakeFlask:
        def run(self, **kwargs):
            runs.append("flask")

    monkeypatch.setattr(rulevis, "Timer", FakeTimer)
    monkeypatch.setattr(rulevis, "create_app", lambda *args: FakeFlask())
    instance._Rulevis__run_flask_app()
    assert timers[0].daemon is True
    assert runs == ["timer", "flask"]


def test_close_is_idempotent(tmp_path):
    instance = Rulevis([str(tmp_path)])
    paths = [instance.graph_path, instance.stats_path, instance.heatmap_path]
    instance.close()
    instance.close()
    assert all(not os.path.exists(path) for path in paths)
