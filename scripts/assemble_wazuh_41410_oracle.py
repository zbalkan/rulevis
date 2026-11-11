"""Assembled independently captured native Wazuh 4.14.10 observations.

The assembler never synthesizes missing observations from RuleVis predictions.
Every scenario requires a GDB snapshot and the exact native configuration
artifacts used for that invocation. The output matches compare_suite().
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from internal.differential import WAZUH_VERSION, load_fixture, normalize_snapshot
from scripts.render_wazuh_41410_rules import render_rules


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assemble(
    *, fixture: Path, captures: Path, configs: Path, binary: Path,
) -> dict:
    suite, fixture_sha256 = load_fixture(fixture)
    if not binary.is_file():
        raise ValueError("Compiled native analysisd binary is required")

    observed = {}
    per_scenario_configs = {}
    for scenario in suite["scenarios"]:
        scenario_id = scenario["id"]
        if not scenario_id or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
            for char in scenario_id
        ):
            raise ValueError("Unsafe scenario identifier")
        raw_path = captures / (scenario_id + ".json")
        if not raw_path.is_file():
            raise ValueError(f"Missing native GDB capture: {scenario_id}")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        if raw.get("capture_format") != "gdb_wazuh_41410_v1":
            raise ValueError(f"Unsupported native capture format: {scenario_id}")
        if raw.get("scenario_id") != scenario_id:
            raise ValueError(f"Native scenario identity mismatch: {scenario_id}")
        native = raw["snapshot"]
        if native.get("unexpected_rule_ids") != []:
            raise ValueError(f"Unexpected rules loaded by native manager: {scenario_id}")
        if type(native.get("native_occurrence_count")) is not int or native["native_occurrence_count"] < 1:
            raise ValueError(f"Invalid native occurrence count: {scenario_id}")
        snapshot = normalize_snapshot(native)
        rule_ids = {str(rule["id"]) for rule in scenario["rules"]}
        if not set(snapshot["accepted_rules"]) <= rule_ids:
            raise ValueError(f"Unexpected accepted rule IDs: {scenario_id}")
        for row in snapshot["attachments"]:
            if row["parent_rule_id"] not in rule_ids or row["child_rule_id"] not in rule_ids:
                raise ValueError(f"Unexpected structural rule IDs: {scenario_id}")
        for row in snapshot["registrations"]:
            if row["source_rule_id"] not in rule_ids or row["consumer_rule_id"] not in rule_ids:
                raise ValueError(f"Unexpected history rule IDs: {scenario_id}")
        observed[scenario_id] = snapshot

        config_dir = configs / scenario_id
        native_rules = config_dir / "rules.xml"
        ossec_config = config_dir / "ossec.conf"
        if not native_rules.is_file() or not ossec_config.is_file():
            raise ValueError(f"Missing native config snapshot: {scenario_id}")
        if native_rules.read_text(encoding="utf-8") != render_rules(scenario):
            raise ValueError(f"Rules XML differs from the pinned fixture: {scenario_id}")
        per_scenario_configs[scenario_id] = {
            "rules_sha256": sha256_file(native_rules),
            "ossec_conf_sha256": sha256_file(ossec_config),
        }

    # This canonical digest records every scenario's effective config pair,
    # rather than incorrectly hashing one config for the whole suite.
    config_bytes = json.dumps(
        per_scenario_configs, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "schema_version": 1,
        "provenance": {
            "engine": "compiled_wazuh_analysisd",
            "wazuh_version": WAZUH_VERSION,
            "fixture_sha256": fixture_sha256,
            "binary_sha256": sha256_file(binary),
            "ruleset_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
            "per_scenario_config_sha256": per_scenario_configs,
            "capture_method": "GDB _setlevels RuleNode/RuleInfo snapshot v1",
        },
        "scenarios": observed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--configs", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(
            fixture=args.fixture, captures=args.captures,
            configs=args.configs, binary=args.binary,
        )
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (KeyError, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Native oracle assembly failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
