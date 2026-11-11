#!/usr/bin/env python3
"""Install one differential fixture into a dedicated disposable analysisd root.

This preparer is deliberately limited to a caller-created test directory.
The runner supplies the same directory as GDB's working directory and as
analysisd's -D chroot. No Wazuh manager package or services are installed.
"""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

CONFIG = """<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
  <ruleset>
    <decoder_include>ruleset/decoders/0006-json_decoders.xml</decoder_include>
    <decoder_include>ruleset/decoders/0025-apache_decoders.xml</decoder_include>
    <rule_include>etc/rules/rules.xml</rule_include>
  </ruleset>
</ossec_config>
"""


def prepare(scenario: str, rendered: Path, evidence: Path, root: Path) -> None:
    if not scenario or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in scenario):
        raise ValueError("Invalid scenario ID")
    root = root.resolve(strict=True)
    marker = root / ".rulevis-native-test-root"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != "Wazuh 4.14.10 disposable CI":
        raise ValueError("Refusing to modify an unmarked runtime root")
    if root == Path("/var/ossec") or root == Path("/"):
        raise ValueError("Refusing a production or system runtime root")
    rules = root / "etc/rules/rules.xml"
    config = root / "etc/ossec.conf"
    if not rendered.is_file() or not evidence.is_dir():
        raise ValueError("Fixture and evidence directory must exist")
    rules.parent.mkdir(parents=True, exist_ok=True)
    config.parent.mkdir(parents=True, exist_ok=True)
    # Never preserve an old scenario's configuration or additional includes.
    rules.write_bytes(rendered.read_bytes())
    config.write_text(CONFIG, encoding="utf-8")
    shutil.copy2(rules, evidence / "rules.xml")
    shutil.copy2(config, evidence / "ossec.conf")
    print(f"Isolated fixture installed: {scenario} in {root}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("rendered", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    prepare(args.scenario, args.rendered, args.evidence, Path.cwd())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
