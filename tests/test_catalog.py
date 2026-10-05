import pytest

from internal.catalog import (
    DEFAULT_CATEGORY,
    normalize_rule_id,
    os_word_match,
    wazuh_load_priority,
    wazuh_runtime_level,
)
from internal.generator import GraphGenerator


@pytest.mark.parametrize(
    "level,accuracy,load_priority,runtime_level",
    [
        (12, 1, 1200, 12),
        (12, 0, 12, 12),
        (0, 1, 9900, 0),
        (0, 0, 99, 99),
    ],
)
def test_wazuh_level_transformation(
    level, accuracy, load_priority, runtime_level
):
    assert wazuh_load_priority(level, accuracy) == load_priority
    assert wazuh_runtime_level(load_priority) == runtime_level


@pytest.mark.parametrize(
    "pattern,value,expected",
    [
        ("authentication", "syslog,authentication_failed,", True),
        ("AUTHENTICATION", "syslog,authentication_failed,", True),
        ("^syslog", "syslog,authentication_failed,", True),
        ("^authentication", "syslog,authentication_failed,", False),
        ("audit|authentication", "syslog,authentication_failed,", True),
        ("missing|audit", "syslog,authentication_failed,", False),
    ],
)
def test_os_word_match_matches_wazuh_group_semantics(
    pattern, value, expected
):
    assert os_word_match(pattern, value) is expected


def test_catalog_preserves_source_order_and_overwrite(tmp_path, monkeypatch):
    base = tmp_path / "00-base.xml"
    overwrite = tmp_path / "99-overwrite.xml"

    base.write_text(
        """
<group name="base,">
  <rule id="100100" level="3" accuracy="0" noalert="1">
    <if_level>2</if_level>
    <description>Base</description>
    <group>child_group,</group>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )
    overwrite.write_text(
        """
<group name="custom,">
  <rule id="100100" level="8" overwrite="yes">
    <description>Overwrite</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = GraphGenerator(
        [str(tmp_path)],
        str(tmp_path / "graph.pickle"),
    )
    monkeypatch.setattr(
        generator,
        "get_all_xml_files",
        lambda: [str(base), str(overwrite)],
    )

    generator.build_graph_from_xml()

    assert len(generator.catalog.declarations) == 2

    original, replacement = generator.catalog.declarations

    assert original.sequence == 0
    assert original.rule_id == "100100"
    assert original.source_level == 3
    assert original.load_priority == 3
    assert original.accuracy == 0
    assert original.noalert is True
    assert original.overwrite is False
    assert original.if_level == 2
    assert original.runtime_group == "base,child_group,"
    assert original.display_groups == ("base", "child_group")

    assert replacement.sequence == 1
    assert replacement.rule_id == "100100"
    assert replacement.source_level == 8
    assert replacement.load_priority == 800
    assert replacement.overwrite is True
    assert replacement.runtime_group == "custom,"


def test_catalog_concatenates_wazuh_selector_values(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="source,">
  <rule id="100200" level="5">
    <if_group>auth</if_group>
    <if_group>|audit</if_group>
    <if_sid>100001,</if_sid>
    <if_sid> 100002</if_sid>
    <description>Concatenated selectors</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = GraphGenerator(
        [str(tmp_path)],
        str(tmp_path / "graph.pickle"),
    )
    generator.build_graph_from_xml()

    declaration = generator.catalog.declarations[0]

    assert declaration.if_group == "auth|audit"
    assert declaration.if_sid == "100001, 100002"



@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", "1"),
        ("000001", "1"),
        ("999999", "999999"),
        ("1000000", None),
        ("abc", None),
        ("-1", None),
        ("", None),
    ],
)
def test_rule_id_normalization_matches_wazuh_constraints(value, expected):
    assert normalize_rule_id(value) == expected


def test_catalog_defaults_omitted_category_to_syslog(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="root,">
  <rule id="100300" level="5">
    <description>No explicit category</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = GraphGenerator(
        [str(tmp_path)],
        str(tmp_path / "graph.pickle"),
    )
    generator.build_graph_from_xml()

    declaration = generator.catalog.declarations[0]
    assert declaration.category == DEFAULT_CATEGORY


def test_catalog_accumulates_nested_runtime_groups(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="outer,">
  <group name="inner,">
    <rule id="100301" level="5">
      <group>local,</group>
      <description>Nested rule</description>
    </rule>
  </group>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = GraphGenerator(
        [str(tmp_path)],
        str(tmp_path / "graph.pickle"),
    )
    generator.build_graph_from_xml()

    declaration = generator.catalog.declarations[0]
    assert declaration.runtime_group == "outer,inner,local,"
    assert declaration.display_groups == ("outer", "inner", "local")
