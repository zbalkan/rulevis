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


def test_if_group_attachment_is_preserved_across_group_overwrite(tmp_path):
    source = tmp_path / "rules.xml"
    source.write_text(
        '<group name="authentication_failed,">'
        '<rule id="100100" level="3"><description>Parent</description></rule>'
        '</group>'
        '<group name="children,"><rule id="100101" level="4">'
        '<if_group>authentication</if_group><description>Before</description>'
        '</rule></group>'
        '<group name="beta,"><rule id="100100" level="3" overwrite="yes">'
        '<description>Overwritten</description></rule></group>'
        '<group name="children,"><rule id="100102" level="4">'
        '<if_group>authentication</if_group><description>After</description>'
        '</rule></group>', encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert generator.G.has_edge("100100", "100101")
    edges = generator.G.get_edge_data("100100", "100102")
    assert edges is not None
    assert any(
        edge["relation_type"] == "if_group"
        and edge["load_order_candidate"] is False
        for edge in edges.values()
    )


def test_temporal_if_matched_group_keeps_declarative_links(tmp_path):
    source = tmp_path / "temporal.xml"
    source.write_text(
        '<group name="temporal,"><rule id="100201" level="4">'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Temporal dependent</description></rule></group>'
        '<group name="auth,"><rule id="100200" level="3">'
        '<description>Historical source</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    edges = generator.G.get_edge_data("100200", "100201")
    assert edges is not None
    assert any(
        edge["relation_type"] == "if_matched_group"
        for edge in edges.values()
    )


def test_if_group_matches_future_declaration_without_runtime_candidate(tmp_path):
    path = tmp_path / "future.xml"
    path.write_text(
        '<group name="children,"><rule id="100111" level="4">'
        '<if_group>authentication</if_group>'
        '<description>Child first</description></rule></group>'
        '<group name="authentication_failed,">'
        '<rule id="100110" level="3">'
        '<description>Parent second</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    edges = generator.G.get_edge_data("100110", "100111")

    assert edges is not None
    assert any(
        data["relation_type"] == "if_group"
        and data["load_order_candidate"] is False
        for data in edges.values()
    )


def test_overwrite_history_preserves_source_selector_links(tmp_path):
    source = tmp_path / "history.xml"
    source.write_text(
        '<group name="authentication_failed,">'
        '<rule id="100200" level="3">'
        '<description>Parent</description></rule></group>'
        '<group name="beta,">'
        '<rule id="100200" level="3" overwrite="yes">'
        '<description>Updated parent</description></rule></group>'
        '<group name="children,">'
        '<rule id="100201" level="4">'
        '<if_group>authentication</if_group>'
        '<description>Child after overwrite</description>'
        '</rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    edges = generator.G.get_edge_data("100200", "100201")

    assert edges is not None
    assert any(
        data["relation_type"] == "if_group"
        and data["load_order_candidate"] is False
        for data in edges.values()
    )


def test_early_overwrite_runtime_group_is_a_declared_reference(tmp_path):
    (tmp_path / "00-overwrite.xml").write_text(
        '<group name="authentication_failed,">'
        '<rule id="100300" level="5" overwrite="yes">'
        '<description>Updated parent</description></rule></group>',
        encoding="utf-8",
    )
    (tmp_path / "10-base.xml").write_text(
        '<group name="beta,"><rule id="100300" level="3">'
        '<description>Original parent</description></rule></group>',
        encoding="utf-8",
    )
    (tmp_path / "20-child.xml").write_text(
        '<group name="child,"><rule id="100301" level="4">'
        '<if_group>authentication</if_group>'
        '<description>Historical selector</description></rule>'
        '<rule id="100302" level="4"><if_group>beta</if_group>'
        '<description>Current scanned selector</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    auth_edges = generator.G.get_edge_data("100300", "100301")
    assert auth_edges is not None
    assert any(
        edge["relation_type"] == "if_group"
        and edge["load_order_candidate"] is False
        for edge in auth_edges.values()
    )
    beta_edges = generator.G.get_edge_data("100300", "100302")
    assert beta_edges is not None
    assert any(
        edge["relation_type"] == "if_group"
        and edge["load_order_candidate"] is True
        for edge in beta_edges.values()
    )
