"""Executed the read-only GDB probe against one configured Wazuh scenario.

The caller must prepare an isolated Wazuh 4.14.10 manager with that scenario's
rules XML and ossec.conf. This runner does not alter a running manager.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from internal.differential import load_fixture


PROBE = Path(__file__).resolve().with_name("gdb_wazuh_41410_capture.py")


def run_capture(
    *, fixture: Path, scenario_id: str, binary: Path, output: Path,
    gdb: str = "gdb", timeout: int = 120,
    analysisd_args: tuple[str, ...] = ("-t",),
) -> None:
    suite, _ = load_fixture(fixture)
    if scenario_id not in {case["id"] for case in suite["scenarios"]}:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    if not binary.is_file():
        raise ValueError("Native Wazuh analysisd binary not found")
    if output.exists():
        raise ValueError("Refusing to overwrite an existing native capture")
    if timeout < 1:
        raise ValueError("Timeout must be a positive number of seconds")
    if not PROBE.is_file():
        raise ValueError("Native GDB probe file not found")
    if not output.parent.is_dir():
        raise ValueError("Native capture output directory does not exist")
    env = dict(os.environ)
    env.update({
        "RULEVIS_NATIVE_SCENARIO": str(fixture.resolve()),
        "RULEVIS_NATIVE_SCENARIO_ID": scenario_id,
        "RULEVIS_NATIVE_OUTPUT": str(output.resolve()),
    })
    command = [
        gdb, "--batch", "--quiet", "--nx",
        "-x", str(PROBE),
        "-ex", "run",
        "--args", str(binary.resolve()), *analysisd_args,
    ]
    try:
        result = subprocess.run(
            command, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output.unlink(missing_ok=True)
        raise RuntimeError("Native GDB probe timed out") from exc
    if result.returncode != 0 or not output.is_file():
        output.unlink(missing_ok=True)
        raise RuntimeError(
            f"Native GDB probe did not produce a snapshot (exit {result.returncode}): "
            + (result.stderr or result.stdout)[-1000:]
        )
    try:
        observed = json.loads(output.read_text(encoding="utf-8"))
        if (
            observed.get("capture_format") != "gdb_wazuh_41410_v1"
            or observed.get("scenario_id") != scenario_id
            or not isinstance(observed.get("snapshot"), dict)
        ):
            raise ValueError("GDB emitted an invalid capture envelope")
    except (OSError, ValueError, TypeError) as exc:
        output.unlink(missing_ok=True)
        raise ValueError("Invalid native GDB snapshot") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--analysisd-arg", action="append", default=None,
        help="Native binary argument (repeat as needed); default -t",
    )
    args = parser.parse_args()
    try:
        run_capture(
            fixture=args.fixture, scenario_id=args.scenario,
            binary=args.binary, output=args.output,
            gdb=args.gdb, timeout=args.timeout,
            analysisd_args=tuple(args.analysisd_arg or ["-t"]),
        )
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(2, f"Native GDB capture failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
