import xml.etree.ElementTree as ET

import pytest

from internal.generator import GraphGenerator


def make_generator(tmp_path):
    return GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))


@pytest.mark.parametrize(
    "tag,value",
    [
        ("if_matched_sid", "100001"),
        ("if_matched_group", "authentication"),
        ("if_matched_regex", "failed"),
        ("check_diff", ""),
        ("if_fts", ""),
    ],
)
def test_temporal_tags_without_attributes_are_not_temporal(
    tmp_path, tag, value
):
    element = ET.fromstring(
        f'<rule id="100100" level="5"><{tag}>{value}</{tag}></rule>'
    )

    assert make_generator(tmp_path).is_temporal_rule(element) is False


@pytest.mark.parametrize(
    "attribute",
    ["frequency", "timeframe"],
)
def test_temporal_rule_attributes_mark_rule_temporal(
    tmp_path, attribute
):
    element = ET.fromstring(
        f'<rule id="100100" level="5" {attribute}="60">'
        '<same_field>srcip</same_field>'
        '</rule>'
    )

    assert make_generator(tmp_path).is_temporal_rule(element) is True


def test_temporal_modifiers_without_state_are_not_temporal(tmp_path):
    element = ET.fromstring(
        '<rule id="100100" level="5">'
        '<same_field>srcip</same_field>'
        '<different_field>dstip</different_field>'
        '<global_frequency />'
        '</rule>'
    )

    assert make_generator(tmp_path).is_temporal_rule(element) is False


def test_build_graph_preserves_regex_condition_verbatim(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="regex_test,">
  <rule id="100001" level="3">
    <regex type="pcre2">foo<bar&baz</regex>
    <description>Regex condition</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    generator.build_graph_from_xml()

    conditions = generator.G.nodes["100001"]["conditions"]
    assert conditions == [
        {
            "tag": "regex",
            "value": "foo<bar&baz",
            "attributes": {"type": "pcre2"},
        }
    ]


def test_build_graph_collects_atomic_conditions_and_metadata(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="outer,">
  <rule id="100010" level="7" maxsize="2048">
    <decoded_as>json</decoded_as>
    <field name="event.action" negate="yes">^allow$</field>
    <description>First part</description>
    <description>second part</description>
    <group>inner,</group>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    generator.build_graph_from_xml()
    node = generator.G.nodes["100010"]

    assert node["description"] == "First part second part"
    assert node["groups"] == ["outer", "inner"]
    assert node["level"] == "7"
    assert node["temporal"] is False
    assert node["conditions"] == [
        {"tag": "maxsize", "value": "2048", "kind": "rule_attribute"},
        {"tag": "decoded_as", "value": "json"},
        {
            "tag": "field",
            "value": "^allow$",
            "attributes": {"name": "event.action", "negate": "yes"},
        },
    ]


def test_if_group_resolution_is_independent_of_file_order(tmp_path, monkeypatch):
    child = tmp_path / "00-child.xml"
    parent = tmp_path / "99-parent.xml"

    child.write_text(
        """
<group name="children,">
  <rule id="100020" level="5">
    <if_group>parent_group</if_group>
    <description>Child</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )
    parent.write_text(
        """
<group name="parent_group,">
  <rule id="100019" level="3">
    <decoded_as>json</decoded_as>
    <description>Parent</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    monkeypatch.setattr(
        generator,
        "get_all_xml_files",
        lambda: [str(child), str(parent)],
    )
    generator.build_graph_from_xml()

    edge_data = generator.G.get_edge_data("100019", "100020")
    assert edge_data is not None
    assert {edge["relation_type"] for edge in edge_data.values()} == {
        "if_group"
    }


def test_overwrite_replaces_local_conditions_but_keeps_parent(tmp_path, monkeypatch):
    base = tmp_path / "00-base.xml"
    overwrite = tmp_path / "99-overwrite.xml"

    base.write_text(
        """
<group name="base,">
  <rule id="100000" level="1">
    <decoded_as>json</decoded_as>
    <description>Parent</description>
  </rule>
  <rule id="100100" level="3">
    <if_sid>100000</if_sid>
    <match>old-value</match>
    <description>Old description</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )
    overwrite.write_text(
        """
<group name="local,">
  <rule id="100100" level="8" overwrite="yes">
    <if_sid>999999</if_sid>
    <match>new-value</match>
    <description>New description</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    monkeypatch.setattr(
        generator,
        "get_all_xml_files",
        lambda: [str(base), str(overwrite)],
    )
    generator.build_graph_from_xml()

    node = generator.G.nodes["100100"]
    assert node["level"] == "8"
    assert node["description"] == "New description"
    assert [(c["tag"], c["value"]) for c in node["conditions"]] == [
        ("if_sid", "100000"),
        ("match", "new-value"),
    ]

    edge_data = generator.G.get_edge_data("100000", "100100")
    assert edge_data is not None
    assert {edge["relation_type"] for edge in edge_data.values()} == {
        "if_sid"
    }
    assert generator.G.get_edge_data("999999", "100100") is None


def test_synthetic_root_and_children_are_precomputed(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="root_test,">
  <rule id="100200" level="3">
    <description>Top level</description>
  </rule>
  <rule id="100201" level="4">
    <if_sid>100200</if_sid>
    <description>Child</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    generator.build_graph_from_xml()

    assert generator.G.nodes["0"]["temporal"] is False
    assert generator.G.has_edge("0", "100200")
    assert generator.G.nodes["100200"]["children_ids"] == ["100201"]


def test_if_group_edge_keeps_selector(tmp_path):
    rules = tmp_path / "rules.xml"
    rules.write_text(
        """
<group name="parent_group,">
  <rule id="100300" level="3">
    <description>Parent</description>
  </rule>
</group>
<group name="child_group,">
  <rule id="100301" level="4">
    <if_group>parent_group</if_group>
    <description>Child</description>
  </rule>
</group>
""".strip(),
        encoding="utf-8",
    )

    generator = make_generator(tmp_path)
    generator.build_graph_from_xml()

    edge_data = generator.G.get_edge_data("100300", "100301")
    assert edge_data is not None
    assert list(edge_data.values()) == [
        {
            "relation_type": "if_group",
            "selector": "parent_group",
        }
    ]
