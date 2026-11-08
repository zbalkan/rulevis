import pytest

from internal.catalog import os_match
from internal.generator import GraphGenerator


@pytest.mark.parametrize(
    "pattern,value,expected",
    [
        ("authentication", "syslog,authentication_failed,", True),
        ("^authentication", "syslog,authentication_failed,", False),
        ("^syslog", "syslog,authentication_failed,", True),
        ("authentication_failed$", "syslog,authentication_failed,", False),
        ("failed,$", "syslog,authentication_failed,", True),
        ("^syslog,authentication_failed,$", "syslog,authentication_failed,", True),
        ("missing|AUTHENTICATION", "syslog,authentication_failed,", True),
        ("!authentication", "syslog,authentication_failed,", False),
        ("!missing", "syslog,authentication_failed,", True),
    ],
)
def test_os_match_mirrors_temporal_group_compilation(pattern, value, expected):
    assert os_match(pattern, value) is expected


def test_temporal_group_uses_os_match_on_full_runtime_group_string(tmp_path):
    (tmp_path / "temporal.xml").write_text(
        '<group name="audit,authentication_failed,">'
        '<rule id="100910" level="3"><description>Source</description></rule>'
        '</group>'
        '<group name="children,"><rule id="100911" level="7">'
        '<if_matched_group>^audit,authentication_failed,$</if_matched_group>'
        '<description>Temporal</description></rule>'
        '<rule id="100912" level="7">'
        '<if_matched_group>missing|AUTHENTICATION</if_matched_group>'
        '<description>Alternative</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    for child in ("100911", "100912"):
        edges = generator.G.get_edge_data("100910", child)
        assert edges is not None
        assert any(
            edge["relation_type"] == "if_matched_group"
            and edge["load_order_candidate"] is True
            for edge in edges.values()
        )


def test_temporal_future_parent_remains_declared_only(tmp_path):
    (tmp_path / "temporal.xml").write_text(
        '<group name="children,"><rule id="100920" level="7">'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Temporal</description></rule></group>'
        '<group name="auth,"><rule id="100921" level="3">'
        '<description>Later</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    edges = generator.G.get_edge_data("100921", "100920")
    assert edges is not None
    assert any(
        edge["relation_type"] == "if_matched_group"
        and edge["load_order_candidate"] is False
        for edge in edges.values()
    )


def test_repeated_sid_level_and_temporal_group_tags_are_concatenated(tmp_path):
    (tmp_path / "repeated.xml").write_text(
        '<group name="levels,">'
        '<rule id="100931" level="12"><description>Level parent</description></rule>'
        '<rule id="100932" level="4"><if_level>1</if_level><if_level>2</if_level>'
        '<description>Level child</description></rule>'
        '<rule id="100933" level="3"><description>SID parent</description></rule>'
        '<rule id="100934" level="5">'
        '<if_sid>100931,</if_sid><if_sid> 100933</if_sid>'
        '<description>SID child</description></rule>'
        '<rule id="100935" level="7">'
        '<if_matched_group>missing|</if_matched_group>'
        '<if_matched_group>levels</if_matched_group>'
        '<description>Temporal child</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    graph = generator.G

    level = graph.get_edge_data("100931", "100932")
    assert level is not None
    assert any(
        edge["relation_type"] == "if_level" and edge["selector"] == "12"
        for edge in level.values()
    )
    for parent in ("100931", "100933"):
        assert any(
            edge["relation_type"] == "if_sid"
            for edge in graph.get_edge_data(parent, "100934").values()
        )
    assert any(
        edge["relation_type"] == "if_matched_group"
        and edge["selector"] == "missing|levels"
        for edge in graph.get_edge_data("100931", "100935").values()
    )
