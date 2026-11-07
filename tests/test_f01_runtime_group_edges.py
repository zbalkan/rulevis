"""Declare group relationships separately from scan-order eligibility."""
from internal.generator import GraphGenerator


def _group_candidate(graph, parent, child):
    edges = graph.get_edge_data(parent, child) or {}
    return next(
        data["load_order_candidate"]
        for data in edges.values()
        if data["relation_type"] == "if_group"
    )


def test_group_edges_preserve_declarations_and_flag_load_order(tmp_path):
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
    assert graph.has_edge("100101", "100100")
    assert _group_candidate(graph, "1", "100100") is True
    assert _group_candidate(graph, "100101", "100100") is False
    assert _group_candidate(graph, "100100", "100101") is True


def test_existing_group_edges_survive_later_overwrite(tmp_path, monkeypatch):
    base = tmp_path / "01-base.xml"
    child = tmp_path / "02-child.xml"
    update = tmp_path / "03-overwrite.xml"
    later = tmp_path / "04-later.xml"
    base.write_text(
        '<group name="alpha,"><rule id="100100" level="3">'
        '<description>Parent</description></rule></group>',
        encoding="utf-8",
    )
    child.write_text(
        '<group name="children,"><rule id="100101" level="4">'
        '<if_group>alpha</if_group><description>Child</description>'
        '</rule></group>', encoding="utf-8",
    )
    update.write_text(
        '<group name="beta,"><rule id="100100" level="3" overwrite="yes">'
        '<description>Updated parent</description></rule></group>',
        encoding="utf-8",
    )
    later.write_text(
        '<group name="children,"><rule id="100102" level="4">'
        '<if_group>alpha</if_group><description>Later child</description>'
        '</rule></group>', encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    monkeypatch.setattr(
        generator, "get_all_xml_files",
        lambda: [str(base), str(child), str(update), str(later)],
    )
    generator.build_graph_from_xml()

    assert generator.G.has_edge("100100", "100101")
    assert generator.G.has_edge("100100", "100102")
    assert _group_candidate(generator.G, "100100", "100101") is True
    assert _group_candidate(generator.G, "100100", "100102") is False


def test_overwrite_scanned_before_base_preserves_declared_group(tmp_path):
    (tmp_path / "00-overwrite.xml").write_text(
        '<group name="new_group,"><rule id="100200" level="5" '
        'overwrite="yes"><description>Updated parent</description>'
        '</rule></group>',
        encoding="utf-8",
    )
    (tmp_path / "10-base.xml").write_text(
        '<group name="old_group,"><rule id="100200" level="3">'
        '<description>Original parent</description></rule></group>',
        encoding="utf-8",
    )
    (tmp_path / "20-children.xml").write_text(
        '<group name="child,">'
        '<rule id="100201" level="4"><if_group>new_group</if_group>'
        '<description>Declared new-group child</description></rule>'
        '<rule id="100202" level="4"><if_group>old_group</if_group>'
        '<description>Scanned base-group child</description></rule>'
        '</group>',
        encoding="utf-8",
    )

    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert generator.G.nodes["100200"]["groups"] == ["new_group"]
    assert generator.G.has_edge("100200", "100201")
    assert _group_candidate(generator.G, "100200", "100201") is False
    assert generator.G.has_edge("100200", "100202")
    assert _group_candidate(generator.G, "100200", "100202") is True
