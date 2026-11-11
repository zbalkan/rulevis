"""Differential contract for a *separately observed* Wazuh 4.14.10 rule tree.

Snapshots made by this module are RuleVis predictions. They are never evidence
that a compiled Wazuh process produced the same behavior. The native oracle
must be collected independently, with provenance and a matching fixture digest.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from internal.catalog import RuleCatalog
from internal.historical_registration import build_historical_registrations

SCHEMA_VERSION = 1
WAZUH_VERSION = "4.14.10"
KINDS = {"if_matched_sid", "if_matched_group"}


def load_fixture(path: str | Path) -> tuple[dict[str, Any], str]:
    raw = Path(path).read_bytes()
    suite = json.loads(raw)
    if suite.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported differential fixture schema")
    if suite.get("wazuh_version") != WAZUH_VERSION:
        raise ValueError("Fixture does not target Wazuh 4.14.10")
    names = [item["id"] for item in suite["scenarios"]]
    if len(names) != len(set(names)) or not names:
        raise ValueError("Scenario identifiers must be unique and nonempty")
    return suite, hashlib.sha256(raw).hexdigest()


def _rows(counts: Counter[tuple[str, ...]], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        dict(zip(fields, key), count=count)
        for key, count in sorted(counts.items())
    ]


def predict(scenario: dict[str, Any]) -> dict[str, Any]:
    catalog = RuleCatalog()
    for rule in scenario["rules"]:
        catalog.append(
            rule_id=str(rule["id"]),
            file=str(rule.get("file", "differential.xml")),
            source_level=int(rule.get("level", 5)),
            accuracy=int(rule.get("accuracy", 1)),
            noalert=bool(rule.get("noalert", False)),
            overwrite=bool(rule.get("overwrite", False)),
            runtime_group=str(rule.get("group", "test,")),
            display_groups=list(rule.get("display_groups", [])),
            category=rule.get("category", "syslog"),
            if_sid=rule.get("if_sid"),
            if_level=rule.get("if_level"),
            if_group=rule.get("if_group"),
            if_matched_sid=rule.get("if_matched_sid"),
            if_matched_group=rule.get("if_matched_group"),
            invalid_if_level=rule.get("invalid_if_level"),
            invalid_if_matched_sid=rule.get("invalid_if_matched_sid"),
            conditions=[], temporal_conditions=[],
        )
    projection = build_historical_registrations(catalog)
    model = projection.structural_model
    attachments: Counter[tuple[str, ...]] = Counter()
    for occurrence in model.occurrences.values():
        if occurrence.parent_id is None:
            continue
        parent = model.occurrences[occurrence.parent_id].rule_id
        relation = model.rules[occurrence.rule_id].parent_relation or "unknown"
        attachments[(parent, occurrence.rule_id, relation)] += 1

    # OS_MarkID shares one SID list per RuleInfo, despite visiting multiple
    # occurrences. OS_MarkGroup appends per matching physical occurrence.
    registrations: Counter[tuple[str, ...]] = Counter()
    for reg in projection.registrations:
        key = (reg.source_rule_id, reg.consumer_rule_id, reg.relation_type)
        if reg.relation_type == "if_matched_sid":
            registrations[key] = 1
        else:
            registrations[key] += 1

    return {
        "accepted_rules": sorted(model.rules),
        "attachments": _rows(
            attachments, ("parent_rule_id", "child_rule_id", "relation_type"),
        ),
        "registrations": _rows(
            registrations, ("source_rule_id", "consumer_rule_id", "relation_type"),
        ),
    }


def _normalize_rows(value: Any, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("Differential rows must be arrays")
    seen = set()
    result = []
    for row in value:
        if not isinstance(row, dict) or set(row) != set(fields) | {"count"}:
            raise ValueError("Differential row keys do not match contract")
        key = tuple(row[field] for field in fields)
        if not all(isinstance(item, str) and item for item in key):
            raise ValueError("Differential identifiers must be nonempty strings")
        if key in seen or type(row["count"]) is not int or row["count"] < 1:
            raise ValueError("Duplicate row or invalid occurrence count")
        seen.add(key)
        result.append(dict(zip(fields, key), count=row["count"]))
    return sorted(result, key=lambda row: tuple(row[field] for field in fields))


def normalize_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot must be an object")
    rules = snapshot.get("accepted_rules")
    if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
        raise ValueError("accepted_rules must be a list of strings")
    if len(set(rules)) != len(rules):
        raise ValueError("Duplicate accepted rule")
    return {
        "accepted_rules": sorted(rules),
        "attachments": _normalize_rows(
            snapshot.get("attachments"),
            ("parent_rule_id", "child_rule_id", "relation_type"),
        ),
        "registrations": _normalize_rows(
            snapshot.get("registrations"),
            ("source_rule_id", "consumer_rule_id", "relation_type"),
        ),
    }


def compare_suite(
    fixture: dict[str, Any], fixture_sha256: str, oracle: dict[str, Any],
) -> dict[str, Any]:
    provenance = oracle.get("provenance", {})
    if oracle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Invalid native oracle schema version")
    if provenance.get("engine") != "compiled_wazuh_analysisd":
        raise ValueError("Oracle must identify compiled analysisd, not RuleVis")
    if provenance.get("wazuh_version") != WAZUH_VERSION:
        raise ValueError("Oracle version differs from fixture")
    if provenance.get("fixture_sha256") != fixture_sha256:
        raise ValueError("Oracle is not bound to these exact fixture bytes")
    for required in ("binary_sha256", "ruleset_config_sha256"):
        val = provenance.get(required)
        if not isinstance(val, str) or re.fullmatch(r"[0-9a-fA-F]{64}", val) is None:
            raise ValueError(f"Invalid native oracle SHA-256: {required}")
    if not isinstance(provenance.get("capture_method"), str) or not provenance["capture_method"].strip():
        raise ValueError("Missing native oracle capture method")

    expected_ids = {scenario["id"] for scenario in fixture["scenarios"]}
    observed = oracle.get("scenarios")
    if not isinstance(observed, dict) or set(observed) != expected_ids:
        raise ValueError("Oracle must cover exactly the fixture scenarios")

    results = []
    for scenario in fixture["scenarios"]:
        scenario_id = scenario["id"]
        predicted = normalize_snapshot(predict(scenario))
        actual = normalize_snapshot(observed[scenario_id])
        mismatches = {
            field: {"modeled": predicted[field], "observed": actual[field]}
            for field in predicted if predicted[field] != actual[field]
        }
        results.append({
            "id": scenario_id,
            "status": "match" if not mismatches else "divergence",
            "mismatches": mismatches,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "wazuh_version": WAZUH_VERSION,
        "provenance": provenance,
        "status": "match" if all(not r["mismatches"] for r in results) else "divergence",
        "results": results,
    }
