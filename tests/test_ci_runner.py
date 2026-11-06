"""The Python 3.9 CI job must use an image with an available interpreter."""
from pathlib import Path


def test_python39_runs_on_compatible_ubuntu_image():
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/unit-tests.yml"
    ).read_text(encoding="utf-8")

    assert "runs-on: ${{ matrix.os }}" in workflow
    assert 'python-version: "3.9"\n          os: ubuntu-24.04' in workflow
