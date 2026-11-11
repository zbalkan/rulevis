"""Tested the analysisd-only build artifact policy without compiling Wazuh."""
from __future__ import annotations

import json

import pytest

from scripts import check_wazuh_41410_build as build_check


GDB_RESULT = (
    'Symbol "_setlevels" is a function at address 0x1234.\n'
    "type = struct RuleNode { ... }\n"
    "type = struct RuleInfo { ... }\n"
    "$1 = (struct w_config *) 0x4321\n"
)


def _environment(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    binary = source / "wazuh-analysisd"
    binary.write_bytes(b"\x7fELF" + b"native-test-fixture")
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    def mock_invoke(*args):
        if args[0] == "file":
            return "ELF 64-bit LSB pie executable\n"
        if args[0] == "readelf":
            return "[ 42] .debug_info PROGBITS\n"
        if args[0] == "gdb":
            return GDB_RESULT
        if args[0] == "ldd":
            return "libc.so.6 => /lib/libc.so.6\n"
        raise AssertionError(args)

    monkeypatch.setattr(build_check, "invoke", mock_invoke)
    return source, evidence


def test_validator_uploads_only_requested_executable_and_manifest(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    (source / "libwazuhext.so").write_bytes(b"shared-dependency")
    result = build_check.validate(source, evidence)
    assert result["produced_service_executables"] == ["wazuh-analysisd"]
    assert result["native_oracle_executed"] is False
    assert (evidence / "bin" / "wazuh-analysisd").is_file()
    assert (evidence / "lib" / "libwazuhext.so").is_file()
    saved = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    assert saved["artifact_sha256"]["bin/wazuh-analysisd"]


def test_validator_rejects_unrelated_manager_or_agent_executables(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    (source / "wazuh-agentd").write_bytes(b"\x7fELF" + b"not-allowed")
    with pytest.raises(ValueError, match="Unexpected manager/agent"):
        build_check.validate(source, evidence)


def test_validator_rejects_missing_dwarf_data(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    original = build_check.invoke

    def without_debug(*args):
        if args[0] == "readelf":
            return "[ 42] .text PROGBITS\n"
        return original(*args)

    monkeypatch.setattr(build_check, "invoke", without_debug)
    with pytest.raises(ValueError, match="DWARF"):
        build_check.validate(source, evidence)


def test_validator_rejects_unresolved_gdb_symbols(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    original = build_check.invoke

    def without_symbol(*args):
        if args[0] == "gdb":
            return 'No symbol "_setlevels" in current context.\n'
        return original(*args)

    monkeypatch.setattr(build_check, "invoke", without_symbol)
    with pytest.raises(ValueError, match="GDB could not resolve"):
        build_check.validate(source, evidence)


def test_validator_rejects_missing_runtime_libraries(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    original = build_check.invoke

    def without_library(*args):
        if args[0] == "ldd":
            return "libwazuhext.so => not found\n"
        return original(*args)

    monkeypatch.setattr(build_check, "invoke", without_library)
    with pytest.raises(ValueError, match="Unresolved ELF"):
        build_check.validate(source, evidence)


def test_validator_allows_upstream_required_module_object_files(tmp_path, monkeypatch):
    source, evidence = _environment(tmp_path, monkeypatch)
    module_dir = source / "wazuh_modules"
    module_dir.mkdir()
    (module_dir / "wm_syscollector.o").write_bytes(b"object")
    result = build_check.validate(source, evidence)
    assert result["produced_service_executables"] == ["wazuh-analysisd"]
