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


def test_temporal_sid_synthesizes_structural_if_sid_edge(tmp_path):
    (tmp_path / "sid.xml").write_text(
        '<group name="root,">'
        '<rule id="100940" level="3"><description>Parent</description></rule>'
        '<rule id="100941" level="8" frequency="2" timeframe="60">'
        '<if_matched_sid>100940</if_matched_sid>'
        '<description>Temporal child</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    edges = generator.G.get_edge_data("100940", "100941")
    assert edges is not None
    assert any(
        e["relation_type"] == "if_sid"
        and e["synthesized_from"] == "if_matched_sid"
        for e in edges.values()
    )
    assert any(
        e["relation_type"] == "if_matched_sid"
        for e in edges.values()
    )


def test_temporal_group_has_distinct_structural_and_historical_links(tmp_path):
    (tmp_path / "group.xml").write_text(
        '<group name="auth,"><rule id="100950" level="3">'
        '<description>Parent</description></rule></group>'
        '<group name="other,"><rule id="100951" level="8" '
        'frequency="2" timeframe="60">'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Temporal child</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    edges = generator.G.get_edge_data("100950", "100951")
    assert edges is not None
    assert any(
        e["relation_type"] == "if_group"
        and e["synthesized_from"] == "if_matched_group"
        and e["load_order_candidate"] is True
        for e in edges.values()
    )
    assert any(
        e["relation_type"] == "if_matched_group"
        and e["load_order_candidate"] is True
        for e in edges.values()
    )


def test_explicit_sid_avoids_synthesizing_if_group_from_temporal_selector(
    tmp_path,
):
    (tmp_path / "mixed.xml").write_text(
        '<group name="auth,"><rule id="100960" level="3">'
        '<description>Parent</description></rule></group>'
        '<group name="other,"><rule id="100961" level="8">'
        '<if_sid>100960</if_sid><if_matched_group>auth</if_matched_group>'
        '<description>Temporal child</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    edges = generator.G.get_edge_data("100960", "100961")
    assert edges is not None
    assert any(e["relation_type"] == "if_sid" for e in edges.values())
    assert any(
        e["relation_type"] == "if_matched_group" for e in edges.values()
    )
    assert not any(
        e["relation_type"] == "if_group" for e in edges.values()
    )


@pytest.mark.parametrize(
    "selector,matched",
    [
        ("|missing", True),
        ("missing|", True),
        ("present||missing", True),
        ("!missing|", False),
        ("!missing", True),
    ],
)
def test_native_os_match_empty_alternatives_are_match_all(selector, matched):
    # Wazuh OSMatch_Compile maps an empty branch to _os_strmatch.
    assert os_match(selector, "unrelated_group,") is matched


def test_invalid_temporal_sid_is_reported_and_rejected(tmp_path, caplog):
    (tmp_path / "bad_sid.xml").write_text(
        '<group name="root,">'
        '<rule id="100970" level="4"><description>Parent</description></rule>'
        '<rule id="100971" level="7">'
        '<if_matched_sid>100970,100972</if_matched_sid>'
        '<description>Invalid temporal SID</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    assert "100971" not in generator.G
    assert "if_matched_sid" in caplog.text
    assert "100970,100972" in caplog.text
    from internal.evaluation import EvaluationBuilder
    model = EvaluationBuilder(generator.catalog).build()
    assert "100971" not in model.rules
    assert any(
        issue.code == "INVALID_IF_MATCHED_SID" and issue.rule_id == "100971"
        for issue in model.issues
    )


def test_invalid_repeated_temporal_sid_cannot_be_hidden_by_last_value(
    tmp_path, caplog,
):
    (tmp_path / "bad_sid.xml").write_text(
        '<group name="root,">'
        '<rule id="100980" level="4"><description>Parent</description></rule>'
        '<rule id="100981" level="7">'
        '<if_matched_sid>100980,100982</if_matched_sid>'
        '<if_matched_sid>100980</if_matched_sid>'
        '<description>Invalid repeated temporal SID</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    assert "100981" not in generator.G
    assert "100980,100982" in caplog.text
    from internal.evaluation import EvaluationBuilder
    model = EvaluationBuilder(generator.catalog).build()
    assert "100981" not in model.rules


@pytest.mark.parametrize(
    "temporal_sid,expected_search,expected_shadowed",
    [
        ("100990", "if_matched_sid", "if_matched_sid"),
        ("0", "if_matched_group", None),
    ],
)
def test_historical_sid_precedes_group_without_losing_declared_source(
    tmp_path, temporal_sid, expected_search, expected_shadowed
):
    (tmp_path / "precedence.xml").write_text(
        '<group name="auth,">'
        '<rule id="100990" level="5"><description>Source</description></rule>'
        '</group><group name="child,">'
        '<rule id="100991" level="8" frequency="2" timeframe="60">'
        f'<if_matched_sid>{temporal_sid}</if_matched_sid>'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Mixed historical selectors</description>'
        '</rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()
    graph = generator.G
    assert graph.nodes["100991"]["historical_search"] == expected_search
    group_edges = [
        data for _, target, data in graph.edges(data=True)
        if target == "100991" and data["relation_type"] == "if_matched_group"
    ]
    assert group_edges
    assert all(
        data.get("shadowed_by") == expected_shadowed for data in group_edges
    )
    sid_edges = [
        data for _, target, data in graph.edges(data=True)
        if target == "100991" and data["relation_type"] == "if_matched_sid"
    ]
    assert bool(sid_edges) is (temporal_sid != "0")
    if expected_shadowed:
        # Source history remains inspectable, but not a registered group search.
        assert all(data["shadowed_by"] == "if_matched_sid" for data in group_edges)
    else:
        assert all(data.get("shadowed_by") is None for data in group_edges)


def test_nonhistorical_selector_does_not_shadow_matched_group(tmp_path):
    (tmp_path / "explicit.xml").write_text(
        '<group name="auth,">'
        '<rule id="100992" level="5"><description>Parent</description></rule>'
        '</group><group name="other,">'
        '<rule id="100993" level="8">'
        '<if_sid>100992</if_sid>'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Explicit SID</description></rule>'
        '</group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()
    node = generator.G.nodes["100993"]
    assert node["historical_search"] == "if_matched_group"
    edges = generator.G.get_edge_data("100992", "100993").values()
    assert any(
        data["relation_type"] == "if_matched_group"
        and data.get("shadowed_by") is None
        for data in edges
    )
