"""Ran pinned native Wazuh validation scenarios in an operator-owned sandbox.

A user-provided prepare executable installs ONE fixture into an already
isolated analysisd installation and copies deployed rules.xml and ossec.conf
to the evidence directory. This script never modifies /var/ossec directly,
never substitutes RuleVis predictions for native data, and fails closed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from internal.differential import compare_suite, load_fixture
from scripts.assemble_wazuh_41410_oracle import assemble, sha256_file
from scripts.render_wazuh_41410_rules import render_rules
from scripts.run_wazuh_41410_gdb import run_capture


def run_suite(
    *,
    fixture: Path,
    binary: Path,
    workspace: Path,
    preparer: Path,
    gdb: str = "gdb",
    timeout: int = 120,
    analysisd_args: tuple[str, ...] = ("-t",),
    cwd: Path | None = None,
) -> dict:
    """Execute each scenario from scratch and compare all native captures.

    The preparer receives three positional arguments: scenario ID, rendered
    XML file path, and evidence config directory. It must install the XML
    inside a separately isolated manager, then put byte-identical copies
    of deployed rules.xml and effective ossec.conf in that directory.
    """
    suite, digest = load_fixture(fixture)
    if not binary.is_file() or not preparer.is_file():
        raise ValueError("Compiled analysisd and scenario preparer must exist")
    if cwd is not None and not cwd.is_dir():
        raise ValueError("Native manager working directory does not exist")
    if not 1 <= timeout <= 3600:
        raise ValueError("Native capture timeout must be 1..3600 seconds")
    if workspace.exists():
        raise ValueError("Refusing to reuse existing native evidence directory")

    workspace.mkdir(parents=True)
    configs = workspace / "configs"
    captures = workspace / "captures"
    rendered = workspace / "rendered"
    transcripts = workspace / "transcripts"
    for directory in (configs, captures, rendered, transcripts):
        directory.mkdir()
    (workspace / "fixture.sha256").write_text(digest + "\n", encoding="ascii")
    (workspace / "binary.sha256").write_text(
        sha256_file(binary) + "\n", encoding="ascii"
    )

    for scenario in suite["scenarios"]:
        name = scenario["id"]
        if not name or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                           for char in name):
            raise ValueError(f"Unsafe scenario ID: {name!r}")
        xml = rendered / (name + ".xml")
        expected = render_rules(scenario)
        xml.write_text(expected, encoding="utf-8")
        evidence = configs / name
        evidence.mkdir()

        # Operator hook must install into a disposable manager. It may not
        # silently claim success; verify the copied deployed XML before GDB.
        result = subprocess.run(
            [str(preparer.resolve()), name, str(xml.resolve()), str(evidence.resolve())],
            cwd=cwd, timeout=timeout, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        (transcripts / (name + ".prepare.log")).write_text(
            "STDOUT\n" + result.stdout + "\nSTDERR\n" + result.stderr,
            encoding="utf-8",
        )
        if result.returncode != 0:
            raise RuntimeError(f"Scenario preparation failed: {name} (exit {result.returncode})")
        actual = evidence / "rules.xml"
        configuration = evidence / "ossec.conf"
        if not actual.is_file() or not configuration.is_file():
            raise ValueError(f"Missing deployed configuration evidence: {name}")
        if actual.read_bytes() != xml.read_bytes():
            raise ValueError(f"Prepared rules differ from exact fixture: {name}")
        if not configuration.read_bytes().strip():
            raise ValueError(f"Empty effective ossec.conf evidence: {name}")

        run_capture(
            fixture=fixture, scenario_id=name, binary=binary,
            output=captures / (name + ".json"),
            gdb=gdb, timeout=timeout,
            analysisd_args=analysisd_args, cwd=cwd,
            transcript=transcripts / (name + ".gdb.log"),
        )

    oracle = assemble(
        fixture=fixture, captures=captures, configs=configs, binary=binary,
    )
    report = compare_suite(suite, digest, oracle)
    (workspace / "native-oracle.json").write_text(
        json.dumps(oracle, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (workspace / "differential-report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "basis": "native_capture_artifacts_not_runtime_attestation",
        "fixture_sha256": digest,
        "binary_sha256": sha256_file(binary),
        "files_sha256": {},
    }
    # Manifest covers every retained input, transcript and generated result;
    # changing any artifact after the run is visible to the reviewer.
    for folder in (configs, captures, rendered, transcripts):
        for file in sorted(folder.rglob("*")):
            if file.is_file():
                manifest["files_sha256"][file.relative_to(workspace).as_posix()] = (
                    sha256_file(file)
                )
    for name in ("native-oracle.json", "differential-report.json"):
        manifest["files_sha256"][name] = sha256_file(workspace / name)
    (workspace / "evidence-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--preparer", required=True, type=Path)
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("--gdb", default="gdb")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--analysisd-arg", action="append")
    args = parser.parse_args(argv)
    try:
        report = run_suite(
            fixture=args.fixture, binary=args.binary, workspace=args.workspace,
            preparer=args.preparer, cwd=args.cwd, gdb=args.gdb,
            timeout=args.timeout,
            analysisd_args=tuple(args.analysisd_arg or ("-t",)),
        )
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired,
            KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Native validation not completed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "scenarios": len(report["results"]),
        "divergences": sum(bool(row["mismatches"]) for row in report["results"]),
        "evidence": str(args.workspace.resolve()),
    }, sort_keys=True))
    return 0 if report["status"] == "match" else 1


if __name__ == "__main__":
    raise SystemExit(main())
