"""Visualization group edges follow Wazuh OS_WordMatch selector semantics."""
import pytest

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


@pytest.mark.parametrize(
    "selector,expected",
    [
        ("authentication", True),
        ("AUTHENTICATION", True),
        ("^authentication", True),
        ("^AUTHENTICATION", True),
        ("^missing|AUTHENTICATION", True),
        ("missing|authentication", True),
        ("auth|authentication", True),
        ("^syslog", False),
        ("^failed", False),
        ("missing|audit", False),
        ("auth,beta", False),
        ("authenticated", False),
        ("", False),
        ("   ", False),
        ("|", False),
        ("||", False),
    ],
)
def test_if_group_selector_positive_negative_and_empty_cases(
    tmp_path, selector, expected
):
    source = tmp_path / "selectors.xml"
    source.write_text(
        '<group name="authentication_failed,">'
        '<rule id="100610" level="3"><description>Parent</description>'
        '</rule></group>'
        '<group name="children,"><rule id="100611" level="4">'
        f'<if_group>{selector}</if_group>'
        '<description>Child</description></rule></group>',
        encoding="utf-8",
    )

    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    edges = [
        edge
        for edge in (
            generator.G.get_edge_data("100610", "100611") or {}
        ).values()
        if edge["relation_type"] == "if_group"
    ]

    assert bool(edges) is expected
    if expected:
        assert len(edges) == 1
        assert edges[0]["selector"] == selector
        assert edges[0]["load_order_candidate"] is True


def test_if_group_unicode_case_folding_only_folds_ascii(tmp_path):
    (tmp_path / "unicode.xml").write_text(
        '<group name="Äuth,">'
        '<rule id="100612" level="3"><description>Parent</description>'
        '</rule></group><group name="children,">'
        '<rule id="100613" level="4"><if_group>ÄUTH</if_group>'
        '<description>Matching child</description></rule>'
        '<rule id="100614" level="4"><if_group>äuth</if_group>'
        '<description>Nonmatching child</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert generator.G.has_edge("100612", "100613")
    assert not generator.G.has_edge("100612", "100614")


def test_if_group_repeated_tags_form_one_selector(tmp_path):
    (tmp_path / "repeated.xml").write_text(
        '<group name="audit,"><rule id="100615" level="3">'
        '<description>Parent</description></rule></group>'
        '<group name="child,"><rule id="100616" level="4">'
        '<if_group>missing</if_group><if_group>|audit</if_group>'
        '<description>Child</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    edges = generator.G.get_edge_data("100615", "100616")

    assert edges is not None
    assert len(edges) == 1
    edge = next(iter(edges.values()))
    assert edge["relation_type"] == "if_group"
    assert edge["selector"] == "missing|audit"
    assert edge["load_order_candidate"] is True


def test_if_group_nested_and_local_runtime_groups(tmp_path):
    (tmp_path / "nested.xml").write_text(
        '<group name="outer,"><group name="inner,">'
        '<rule id="100617" level="3"><group>local,</group>'
        '<description>Parent</description></rule></group></group>'
        '<group name="children,">'
        '<rule id="100618" level="4"><if_group>outer|local</if_group>'
        '<description>Child 1</description></rule>'
        '<rule id="100619" level="4"><if_group>inner</if_group>'
        '<description>Child 2</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    for child in ("100618", "100619"):
        edges = generator.G.get_edge_data("100617", child)
        assert edges is not None
        assert len(edges) == 1
        edge = next(iter(edges.values()))
        assert edge["relation_type"] == "if_group"
        assert edge["load_order_candidate"] is True


def test_multiple_overwrites_preserve_declared_history_and_load_snapshots(tmp_path):
    (tmp_path / "history.xml").write_text(
        '<group name="first,"><rule id="100620" level="3">'
        '<description>Base</description></rule></group>'
        '<group name="children,"><rule id="100621" level="4">'
        '<if_group>first</if_group></rule></group>'
        '<group name="second,"><rule id="100620" level="4" overwrite="yes">'
        '<description>Overwrite 1</description></rule></group>'
        '<group name="children,"><rule id="100622" level="4">'
        '<if_group>first</if_group></rule>'
        '<rule id="100623" level="4"><if_group>second</if_group>'
        '</rule></group>'
        '<group name="third,"><rule id="100620" level="5" overwrite="yes">'
        '<description>Overwrite 2</description></rule></group>'
        '<group name="children,"><rule id="100624" level="4">'
        '<if_group>second</if_group></rule>'
        '<rule id="100625" level="4"><if_group>third</if_group>'
        '</rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert generator.G.nodes["100620"]["groups"] == ["third"]
    expected = {
        "100621": True,
        "100622": False,
        "100623": True,
        "100624": False,
        "100625": True,
    }
    for child, available in expected.items():
        edges = generator.G.get_edge_data("100620", child)
        assert edges is not None
        group_edges = [
            edge for edge in edges.values()
            if edge["relation_type"] == "if_group"
        ]
        assert len(group_edges) == 1
        assert group_edges[0]["load_order_candidate"] is available


def test_orphan_overwrite_cannot_create_a_phantom_group_parent(tmp_path):
    (tmp_path / "orphan.xml").write_text(
        '<group name="phantom,"><rule id="100626" level="4" overwrite="yes">'
        '<description>No base</description></rule></group>'
        '<group name="children,"><rule id="100627" level="4">'
        '<if_group>phantom</if_group></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert "100626" not in generator.G
    assert not generator.G.has_edge("100626", "100627")
    assert "100626" not in generator.runtime_group_by_rule
    assert "100626" not in generator.runtime_group_history


def test_duplicate_rule_cannot_contribute_a_different_group(tmp_path):
    (tmp_path / "duplicate.xml").write_text(
        '<group name="original,"><rule id="100628" level="3">'
        '<description>Accepted parent</description></rule></group>'
        '<group name="duplicate,"><rule id="100628" level="3">'
        '<description>Rejected duplicate</description></rule></group>'
        '<group name="children,">'
        '<rule id="100629" level="4"><if_group>duplicate</if_group>'
        '<description>Not attached</description></rule>'
        '<rule id="100630" level="4"><if_group>original</if_group>'
        '<description>Attached</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert not generator.G.has_edge("100628", "100629")
    assert generator.G.has_edge("100628", "100630")
    assert generator.runtime_group_history["100628"] == ["original,"]


@pytest.mark.parametrize(
    "attributes",
    [
        'level="3"',                      # missing ID
        'id="not-numeric" level="3"',     # invalid ID
        'id="1000000" level="3"',        # out-of-range ID
        'id="-1" level="3"',             # negative ID
        'id="100631"',                    # missing level
        'id="100631" level="invalid"',  # invalid level
        'id="100631" level="3" accuracy="invalid"',
    ],
)
def test_invalid_parent_declarations_do_not_create_visual_group_edges(
    tmp_path, attributes
):
    (tmp_path / "invalid.xml").write_text(
        '<group name="invalid_group,">'
        f'<rule {attributes}><description>Invalid parent</description>'
        '</rule></group>'
        '<group name="valid_group,"><rule id="100632" level="3">'
        '<description>Valid parent</description></rule></group>'
        '<group name="children,">'
        '<rule id="100633" level="4"><if_group>invalid_group</if_group>'
        '<description>Unattached child</description></rule>'
        '<rule id="100634" level="4"><if_group>valid_group</if_group>'
        '<description>Attached child</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert set(generator.G.nodes) == {
        "0", "100632", "100633", "100634"
    }
    assert not any(
        edge["relation_type"] == "if_group"
        for _, _, edge in generator.G.in_edges(
            "100633", data=True
        )
    )
    assert generator.G.has_edge("100632", "100634")
    assert generator.G.nodes["100632"]["description"] == "Valid parent"


def test_malformed_xml_file_does_not_prevent_valid_file_parsing(
    tmp_path, caplog
):
    (tmp_path / "00-malformed.xml").write_text(
        '<group name="bad,"><rule id="100635" level="3">',
        encoding="utf-8",
    )
    (tmp_path / "10-valid.xml").write_text(
        '<group name="good,"><rule id="100636" level="3">'
        '<description>Good parent</description></rule></group>'
        '<group name="children,"><rule id="100637" level="4">'
        '<if_group>good</if_group></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert "100635" not in generator.G
    assert generator.G.has_edge("100636", "100637")
    assert any(
        "Error parsing" in record.getMessage()
        and "00-malformed.xml" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize(
    "selector,expected_parents",
    [
        (" authentication ", ("100100",)),
        ("\n\tAUTHENTICATION\t ", ("100100",)),
        ("\t missing|authentication \n", ("100100",)),
        ("  authentication|beta  ", ("100100", "100101")),
    ],
)
def test_if_group_ignores_outer_selector_whitespace(
    tmp_path, selector, expected_parents
):
    (tmp_path / "whitespace.xml").write_text(
        '<group name="authentication_failed,">'
        '<rule id="100100" level="3"><description>Auth</description>'
        '</rule></group>'
        '<group name="beta,"><rule id="100101" level="3">'
        '<description>Beta</description></rule></group>'
        '<group name="children,">'
        '<rule id="100102" level="4">'
        f'<if_group>{selector}</if_group></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    actual = {
        parent: next(
            edge
            for edge in generator.G.get_edge_data(parent, "100102").values()
            if edge["relation_type"] == "if_group"
        )
        for parent in expected_parents
    }

    assert set(actual) == set(expected_parents)
    assert all(edge["load_order_candidate"] is True for edge in actual.values())
    assert all(
        edge["selector"] == selector.strip()
        for edge in actual.values()
    )


def test_canonical_rule_ids_link_sid_temporal_group_and_overwrites(tmp_path):
    (tmp_path / "canonical.xml").write_text(
        '<group name="original,"><rule id="000001" level="3">'
        '<description>Base</description></rule></group>'
        '<group name="children,"><rule id="000002" level="4">'
        '<if_sid>1</if_sid></rule>'
        '<rule id="3" level="4"><if_sid>000001</if_sid></rule>'
        '<rule id="000004" level="5">'
        '<if_matched_sid>000001</if_matched_sid></rule>'
        '</group>'
        '<group name="updated,"><rule id="1" level="6" overwrite="yes">'
        '<description>Canonical overwrite</description></rule></group>'
        '<group name="children,"><rule id="000005" level="4">'
        '<if_group>updated</if_group></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    graph = generator.G

    assert set(graph.nodes) == {"0", "1", "2", "3", "4", "5"}
    assert graph.nodes["1"]["description"] == "Canonical overwrite"
    assert graph.nodes["1"]["groups"] == ["updated"]
    for child in ("2", "3", "4"):
        edges = graph.get_edge_data("1", child)
        assert edges is not None
        assert any(
            edge["relation_type"] == (
                "if_matched_sid" if child == "4" else "if_sid"
            )
            for edge in edges.values()
        )
    group_edges = graph.get_edge_data("1", "5")
    assert group_edges is not None
    assert any(
        edge["relation_type"] == "if_group"
        and edge["load_order_candidate"] is True
        for edge in group_edges.values()
    )


def test_canonical_rule_ids_collapse_duplicate_spellings_and_early_overwrite(
    tmp_path
):
    (tmp_path / "00-overwrite.xml").write_text(
        '<group name="updated,"><rule id="000011" level="6" '
        'overwrite="yes"><description>Early overwrite</description>'
        '</rule></group>',
        encoding="utf-8",
    )
    (tmp_path / "10-base.xml").write_text(
        '<group name="base,"><rule id="11" level="3">'
        '<description>Base</description></rule></group>'
        '<group name="duplicate,"><rule id="000011" level="3">'
        '<description>Duplicate</description></rule></group>'
        '<group name="children,"><rule id="000012" level="4">'
        '<if_sid>000011</if_sid></rule>'
        '<rule id="000013" level="4">'
        '<if_group>updated</if_group></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()

    assert set(generator.G.nodes) == {"0", "11", "12", "13"}
    assert generator.G.nodes["11"]["description"] == "Early overwrite"
    assert generator.G.nodes["11"]["groups"] == ["updated"]
    assert generator.G.has_edge("11", "12")
    group_edges = generator.G.get_edge_data("11", "13")
    assert group_edges is not None
    assert any(
        edge["relation_type"] == "if_group"
        and edge["load_order_candidate"] is False
        for edge in group_edges.values()
    )
    assert "duplicate," not in generator.runtime_group_history["11"]
