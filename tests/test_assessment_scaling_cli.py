"""Smoke-test benchmark entry points against the assessor predicate contract."""
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("scenario", ["wide", "deep", "group"])
def test_assessment_scaling_benchmark_uses_explicit_predicate_policy(scenario):
    repository = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            str(repository / "benchmarks" / "assessment_scaling.py"),
            "--scenario", scenario,
            "--rules", "3",
            "--events", "2",
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    rows = result.stdout.strip().splitlines()
    assert len(rows) == 2
    assert rows[0].startswith("scenario,rules,events,")
    assert rows[1].startswith(f"{scenario},3,2,")
