"""Validated the scope and GDB prerequisites of an analysisd-only Wazuh build.

This check intentionally rejects any other newly produced ELF executables at
the upstream src/ root. Static archives and shared libraries needed by the
analysisd dependency closure are allowed; they are not manager daemons.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def invoke(*args: str) -> str:
    result = subprocess.run(
        list(args), check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout + result.stderr


def validate(source: Path, artifacts: Path) -> dict:
    source = source.resolve()
    artifacts = artifacts.resolve()
    binary = source / "wazuh-analysisd"
    if not binary.is_file():
        raise ValueError("Required wazuh-analysisd ELF binary was not built")
    if not artifacts.is_dir():
        raise ValueError("Evidence directory does not exist")

    kind = invoke("file", "-b", str(binary))
    if "ELF" not in kind or "executable" not in kind:
        raise ValueError("analysisd is not an ELF executable: " + kind)

    other_executables = []
    for item in source.iterdir():
        if not item.is_file() or item == binary:
            continue
        # Check the actual file signature, not just executable permissions.
        if item.read_bytes()[:4] != b"\x7fELF":
            continue
        description = invoke("file", "-b", str(item))
        if "executable" in description:
            other_executables.append(item.name)
    if other_executables:
        raise ValueError(
            "Unexpected manager/agent ELF executables were built: "
            + ", ".join(sorted(other_executables))
        )
    sections = invoke("readelf", "-SW", str(binary))
    if ".debug_info" not in sections:
        raise ValueError("analysisd has no DWARF .debug_info section")
    gdb_commands = (
        "set pagination off",
        "info address _setlevels",
        "ptype RuleNode",
        "ptype RuleInfo",
        "print &Config",
    )
    args = ["gdb", "--batch", "--quiet", "--nx", str(binary)]
    for command in gdb_commands:
        args.extend(("-ex", command))
    transcript = invoke(*args)
    if (
        "No symbol" in transcript
        or "No struct type named" in transcript
        or "No type named" in transcript
        or "<optimized out>" in transcript
        or "Symbol \"_setlevels\"" not in transcript
    ):
        raise ValueError("GDB could not resolve required analysisd symbols:\n" + transcript)
    if "type = " not in transcript:
        raise ValueError("GDB did not expose RuleNode/RuleInfo structures")
    (artifacts / "gdb-symbol-check.txt").write_text(transcript, encoding="utf-8")

    # Preserve Wazuh's $ORIGIN/../lib RPATH in the distributable artifact.
    # ldd against the build-tree ELF alone cannot find libwazuhext.so,
    # because the library has not yet been placed in its runtime layout.
    destination = artifacts / "bin" / binary.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, destination)
    library_dir = artifacts / "lib"
    library_dir.mkdir(exist_ok=True)
    for name in ("libwazuhext.so", "libwazuhshared.so"):
        library = source / name
        if library.is_file():
            shutil.copy2(library, library_dir / name)

    dependencies = invoke("ldd", str(destination))
    if "not found" in dependencies:
        raise ValueError("Unresolved ELF runtime dependency:\\n" + dependencies)
    (artifacts / "ldd.txt").write_text(dependencies, encoding="utf-8")
    manifest = {
        "upstream_version": "4.14.10",
        "target": "wazuh-analysisd",
        "debug": True,
        "produced_service_executables": ["wazuh-analysisd"],
        "artifact_sha256": {
            str(file.relative_to(artifacts)): hashlib.sha256(file.read_bytes()).hexdigest()
            for file in sorted(artifacts.rglob("*"))
            if file.is_file() and file.name not in {"build.log", "manifest.json"}
        },
        "scope": "Selected executable and required static/shared link dependencies",
        "native_oracle_executed": False,
    }
    (artifacts / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(args.source, args.artifacts)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(2, f"Native build validation failed: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
