"""The visual group graph must not invent future or self runtime parents."""
from internal.generator import GraphGenerator


def test_group_edges_exclude_current_and_future_rules(tmp_path):
    source = tmp_path / "groups.xml"
    source.write_text(
        '<group name="loop,"><rule id="1" level="0">'
        '<description>Root</description></rule>'
        '<rule id="100100" level="3"><if_group>loop</if_group>'
        '<description>First</description></rule>'
        '<rule id="100101" level="3"><if_group>loop</if_group>'
        '<description>Second</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    graph = generator.G

    assert graph.has_edge("1", "100100")
    assert graph.has_edge("100100", "100101")
    assert not graph.has_edge("100100", "100100")
    assert not graph.has_edge("100101", "100101")
    assert not graph.has_edge("100101", "100100")
