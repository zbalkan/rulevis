"""Verified native fixture rendering without running a Wazuh manager."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from internal.differential import load_fixture
from scripts.render_wazuh_41410_rules import render_rules


FIXTURE = Path(__file__).parent / "fixtures" / "wazuh_41410_differential.json"


def test_rendered_rule_order_and_attributes_match_scenario():
    suite, _ = load_fixture(FIXTURE)
    for scenario in suite["scenarios"]:
        xml = render_rules(scenario)
        root = ET.fromstring("<root>" + xml + "</root>")
        children = [rule for group in root for rule in group]
        assert [rule.get("id") for rule in children] == [
            str(rule["id"]) for rule in scenario["rules"]
        ]
        assert [group.get("name") for group in root] == [
            rule.get("group", "test,") for rule in scenario["rules"]
        ]
        assert render_rules(scenario) == xml


def test_temporal_and_overwrite_settings_are_preserved():
    suite, _ = load_fixture(FIXTURE)
    for scenario in suite["scenarios"]:
        root = ET.fromstring("<root>" + render_rules(scenario) + "</root>")
        rules = [rule for group in root for rule in group]
        for source, rule in zip(scenario["rules"], rules):
            assert rule.get("overwrite") == ("yes" if source.get("overwrite") else None)
            temporal = source.get("if_matched_sid") is not None or (
                source.get("if_matched_group") is not None
            )
            assert ("frequency" in rule.attrib) is temporal
            for selector in ("if_sid", "if_level", "if_group",
                             "if_matched_sid", "if_matched_group"):
                value = source.get(selector)
                assert rule.findtext(selector) == (str(value) if value is not None else None)
