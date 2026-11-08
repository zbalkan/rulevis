import networkx as nx

from internal.conditions import ATOMIC_RELATION_TYPES, resolve_atomic_paths
from internal.generator import GraphGenerator


def _graph(tmp_path, xml):
    (tmp_path / "rules.xml").write_text(xml, encoding="utf-8")
    generator = GraphGenerator(
        [str(tmp_path)], str(tmp_path / "graph.pickle")
    )
    generator.build_graph_from_xml()
    return generator.G


def _edges(graph, parent, child, relation):
    return [
        data
        for data in (graph.get_edge_data(parent, child) or {}).values()
        if data.get("relation_type") == relation
    ]


def test_if_level_preserves_source_candidates_and_scan_order(tmp_path):
    graph = _graph(
        tmp_path,
        '<group name="levels,">'
        '<rule id="100701" level="8"><description>Eligible early</description></rule>'
        '<rule id="100702" level="6"><description>Ineligible</description></rule>'
        '<rule id="100703" level="7"><if_level>8</if_level>'
        '<description>Threshold child</description></rule>'
        '<rule id="100704" level="9"><description>Eligible future</description></rule>'
        '</group>',
    )

    early = _edges(graph, "100701", "100703", "if_level")
    future = _edges(graph, "100704", "100703", "if_level")

    assert len(early) == 1
    assert len(future) == 1
    assert early[0]["selector"] == "8"
    assert early[0]["load_order_candidate"] is True
    assert future[0]["load_order_candidate"] is False
    assert not _edges(graph, "100702", "100703", "if_level")
    assert not _edges(graph, "100703", "100703", "if_level")


def test_if_level_overwrite_history_does_not_retroactively_change_candidates(
    tmp_path,
):
    graph = _graph(
        tmp_path,
        '<group name="levels,">'
        '<rule id="100711" level="10"><description>Base</description></rule>'
        '<rule id="100711" level="5" overwrite="yes">'
        '<description>Changed priority</description></rule>'
        '<rule id="100712" level="7"><if_level>8</if_level>'
        '<description>Threshold child</description></rule>'
        '<rule id="100711" level="11" overwrite="yes">'
        '<description>Restored priority</description></rule>'
        '<rule id="100713" level="7"><if_level>8</if_level>'
        '<description>Later threshold child</description></rule>'
        '</group>',
    )

    first = _edges(graph, "100711", "100712", "if_level")
    second = _edges(graph, "100711", "100713", "if_level")

    assert len(first) == 1
    assert first[0]["load_order_candidate"] is False
    assert len(second) == 1
    assert second[0]["load_order_candidate"] is True


def test_if_level_preserves_zero_threshold_as_invalid_source_metadata(tmp_path):
    graph = _graph(
        tmp_path,
        '<group name="levels,">'
        '<rule id="100721" level="10"><description>Parent</description></rule>'
        '<rule id="100722" level="7"><if_level>0</if_level>'
        '<description>Invalid threshold</description></rule>'
        '</group>',
    )

    assert graph.nodes["100722"]["if_level"] == "0"
    assert not _edges(graph, "100721", "100722", "if_level")


def test_if_level_is_an_atomic_relationship_not_a_flat_condition():
    graph = nx.MultiDiGraph()
    graph.add_node("0")
    graph.add_node("100731", conditions=[
        {"tag": "field", "value": "^parent$", "kind": "atomic"}
    ])
    graph.add_node("100732", conditions=[
        {"tag": "if_level", "value": "7"},
        {"tag": "field", "value": "^child$", "kind": "atomic"},
    ])
    graph.add_edge("0", "100731", relation_type="root")
    graph.add_edge("100731", "100732", relation_type="if_level", selector="7")

    assert "if_level" in ATOMIC_RELATION_TYPES

    paths = resolve_atomic_paths(graph, "100732")

    assert len(paths) == 1
    assert paths[0]["nodes"] == ["0", "100731", "100732"]
    assert [row["tag"] for row in paths[0]["conditions"]] == ["field", "field"]


def test_declared_group_cycles_remain_visible_after_if_level_support(tmp_path):
    graph = _graph(
        tmp_path,
        '<group name="audit_watch_write,">'
        '<rule id="80790" level="3"><if_group>audit_watch_write</if_group>'
        '<description>First</description></rule>'
        '<rule id="80791" level="3"><if_group>audit_watch_write</if_group>'
        '<description>Second</description></rule>'
        '</group>',
    )
    assert _edges(graph, "80790", "80791", "if_group")
    assert _edges(graph, "80791", "80790", "if_group")
    assert not nx.is_directed_acyclic_graph(graph)
