"""Rendered isolated, ordered Wazuh XML rules from differential scenarios.

Each scenario is intended for its own disposable analysisd configuration.
Do not add the generated template rules (IDs below 10) to a live manager.
"""
from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

from internal.differential import load_fixture

CHILD_ELEMENTS = (
    ("if_sid", "if_sid"),
    ("if_level", "if_level"),
    ("if_group", "if_group"),
    ("if_matched_sid", "if_matched_sid"),
    ("if_matched_group", "if_matched_group"),
)


def render_rules(scenario: dict) -> str:
    blocks: list[str] = []
    for rule in scenario["rules"]:
        group = str(rule.get("group", "test,"))
        wrapper = ET.Element("group", name=group)
        attrib = {
            "id": str(rule["id"]),
            "level": str(rule.get("level", 5)),
        }
        if "accuracy" in rule:
            attrib["accuracy"] = str(rule["accuracy"])
        if rule.get("overwrite"):
            attrib["overwrite"] = "yes"
        if rule.get("noalert"):
            attrib["noalert"] = "1"
        if rule.get("if_matched_sid") is not None or rule.get("if_matched_group") is not None:
            # Retained in event-test fixtures; not evaluated by the structural
            # or historical-registration prediction itself.
            attrib["frequency"] = "2"
            attrib["timeframe"] = "60"
        element = ET.SubElement(wrapper, "rule", attrib)
        for json_key, tag in CHILD_ELEMENTS:
            if rule.get(json_key) is not None:
                ET.SubElement(element, tag).text = str(rule[json_key])
        ET.SubElement(element, "description").text = (
            f"RuleVis differential fixture {scenario['id']} rule {rule['id']}"
        )
        blocks.append(ET.tostring(wrapper, encoding="unicode"))
    return "\n".join(blocks) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    suite, _ = load_fixture(args.fixture)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for case in suite["scenarios"]:
        # Scenario IDs are paths only after rejecting traversal characters.
        name = case["id"]
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in name):
            parser.error(f"Unsafe scenario ID: {name!r}")
        (args.out_dir / f"{name}.xml").write_text(
            render_rules(case), encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
