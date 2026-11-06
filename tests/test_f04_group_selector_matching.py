"""Visualization group edges follow Wazuh OS_WordMatch selector semantics."""
from internal.generator import GraphGenerator


def test_if_group_matches_substrings_and_pipe_alternatives(tmp_path):
    path = tmp_path / "groups.xml"
    path.write_text(
        '<group name="authentication_failed,">'
        '<rule id="100100" level="3"><description>A</description></rule>'
        '</group><group name="beta,">'
        '<rule id="100101" level="3"><description>B</description></rule>'
        '</group><group name="children,">'
        '<rule id="100102" level="4"><if_group>authentication</if_group>'
        '<description>C</description></rule>'
        '<rule id="100103" level="4"><if_group>authentication|beta</if_group>'
        '<description>D</description></rule>'
        '</group>', encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert generator.G.has_edge("100100", "100102")
    assert generator.G.has_edge("100100", "100103")
    assert generator.G.has_edge("100101", "100103")


def test_group_selector_comma_is_not_an_alternative_operator(tmp_path):
    path = tmp_path / "groups.xml"
    path.write_text(
        '<group name="alpha,"><rule id="100100" level="3">'
        '<description>A</description></rule></group>'
        '<group name="child,"><rule id="100101" level="4">'
        '<if_group>alpha,beta</if_group><description>B</description>'
        '</rule></group>', encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    assert not generator.G.has_edge("100100", "100101")
