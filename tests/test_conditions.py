import networkx as nx

from internal.conditions import (
    ATOMIC_RELATION_TYPES,
    enumerate_paths,
)


def test_enumerate_single_atomic_path():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid", selector="A")
    graph.add_edge("B", "C", relation_type="if_sid", selector="B")

    paths = enumerate_paths(graph, "C")

    assert [path["nodes"] for path in paths] == [
        ["0", "A", "B", "C"]
    ]
    assert [
        edge["relation_type"]
        for edge in paths[0]["edges"]
    ] == ["root", "if_sid", "if_sid"]


def test_enumerate_all_branching_atomic_paths():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")
    graph.add_edge("B", "C", relation_type="if_sid")
    graph.add_edge("0", "D", relation_type="root")
    graph.add_edge("D", "E", relation_type="if_sid")
    graph.add_edge("E", "C", relation_type="if_group")
    graph.add_edge("D", "F", relation_type="if_sid")
    graph.add_edge("F", "C", relation_type="if_group")

    paths = enumerate_paths(graph, "C")

    assert [path["nodes"] for path in paths] == [
        ["0", "A", "B", "C"],
        ["0", "D", "E", "C"],
        ["0", "D", "F", "C"],
    ]


def test_path_enumeration_is_cycle_safe():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")
    graph.add_edge("B", "A", relation_type="if_sid")
    graph.add_edge("B", "C", relation_type="if_sid")

    paths = enumerate_paths(graph, "C")

    assert [path["nodes"] for path in paths] == [
        ["0", "A", "B", "C"]
    ]


def test_parallel_relationships_remain_distinct_paths():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "C", relation_type="if_sid", selector="A")
    graph.add_edge(
        "A",
        "C",
        relation_type="if_group",
        selector="group_a",
    )

    paths = enumerate_paths(graph, "C")

    assert len(paths) == 2
    assert {
        path["edges"][-1]["relation_type"]
        for path in paths
    } == {"if_sid", "if_group"}


def test_disallowed_relationships_are_not_followed():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "T", relation_type="if_matched_sid")

    assert enumerate_paths(
        graph,
        "T",
        allowed_relations=ATOMIC_RELATION_TYPES,
    ) == []


def test_flatten_atomic_conditions_preserves_order_and_origin():
    from internal.conditions import flatten_atomic_conditions

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[
            {"tag": "decoded_as", "value": "json"},
            {"tag": "match", "value": "parent"},
        ],
    )
    graph.add_node(
        "B",
        conditions=[
            {"tag": "if_sid", "value": "A"},
            {
                "tag": "field",
                "value": "^deny$",
                "attributes": {"name": "event.action"},
            },
        ],
    )

    rows = flatten_atomic_conditions(
        graph,
        {"nodes": ["0", "A", "B"], "edges": []},
    )

    assert rows == [
        {
            "origin_rule_id": "A",
            "inherited": True,
            "tag": "decoded_as",
            "value": "json",
        },
        {
            "origin_rule_id": "A",
            "inherited": True,
            "tag": "match",
            "value": "parent",
        },
        {
            "origin_rule_id": "B",
            "inherited": False,
            "tag": "field",
            "value": "^deny$",
            "attributes": {"name": "event.action"},
        },
    ]


def test_resolve_atomic_paths_flattens_each_branch():
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[{"tag": "match", "value": "a"}],
    )
    graph.add_node(
        "B",
        conditions=[{"tag": "match", "value": "b"}],
    )
    graph.add_node(
        "C",
        conditions=[{"tag": "field", "value": "c"}],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("0", "B", relation_type="root")
    graph.add_edge("A", "C", relation_type="if_sid")
    graph.add_edge("B", "C", relation_type="if_group")

    paths = resolve_atomic_paths(graph, "C")

    assert [path["condition_count"] for path in paths] == [2, 2]
    assert [
        [row["origin_rule_id"] for row in path["conditions"]]
        for path in paths
    ] == [["A", "C"], ["B", "C"]]


def test_temporal_paths_include_matched_relationships():
    from internal.conditions import resolve_temporal_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    graph.add_node(
        "A",
        conditions=[{"tag": "decoded_as", "value": "json"}],
        temporal_conditions=[],
    )
    graph.add_node(
        "B",
        conditions=[{"tag": "field", "value": "^failed$"}],
        temporal_conditions=[],
    )
    graph.add_node(
        "T",
        conditions=[{"tag": "location", "value": "server"}],
        temporal_conditions=[
            {
                "tag": "frequency",
                "value": "4",
                "kind": "rule_attribute",
            },
            {
                "tag": "timeframe",
                "value": "60",
                "kind": "rule_attribute",
            },
            {"tag": "if_matched_sid", "value": "B"},
        ],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")
    graph.add_edge("B", "T", relation_type="if_matched_sid")

    paths = resolve_temporal_paths(graph, "T")

    assert [path["nodes"] for path in paths] == [["0", "A", "B", "T"]]
    assert [
        (row["origin_rule_id"], row["scope"], row["tag"])
        for row in paths[0]["conditions"]
    ] == [
        ("A", "historical_source", "decoded_as"),
        ("B", "historical_source", "field"),
        ("T", "current_event", "location"),
        ("T", "temporal", "frequency"),
        ("T", "temporal", "timeframe"),
    ]


def test_temporal_path_keeps_atomic_ancestors_current_without_matched_edge():
    from internal.conditions import resolve_temporal_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    graph.add_node(
        "A",
        conditions=[{"tag": "decoded_as", "value": "json"}],
        temporal_conditions=[],
    )
    graph.add_node(
        "T",
        conditions=[{"tag": "field", "value": "x"}],
        temporal_conditions=[
            {"tag": "frequency", "value": "2"},
        ],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "T", relation_type="if_sid")

    path = resolve_temporal_paths(graph, "T")[0]

    assert [
        row["scope"] for row in path["conditions"]
    ] == ["current_event", "current_event", "temporal"]


def test_temporal_ancestor_conditions_are_inherited():
    from internal.conditions import resolve_temporal_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    graph.add_node(
        "T1",
        conditions=[{"tag": "field", "value": "source"}],
        temporal_conditions=[
            {"tag": "frequency", "value": "2"},
            {"tag": "timeframe", "value": "30"},
        ],
    )
    graph.add_node(
        "T2",
        conditions=[],
        temporal_conditions=[
            {"tag": "frequency", "value": "3"},
            {"tag": "timeframe", "value": "60"},
        ],
    )
    graph.add_edge("0", "T1", relation_type="root")
    graph.add_edge("T1", "T2", relation_type="if_matched_sid")

    path = resolve_temporal_paths(graph, "T2")[0]

    assert [
        (row["origin_rule_id"], row["scope"], row["tag"])
        for row in path["conditions"]
    ] == [
        ("T1", "historical_source", "field"),
        ("T1", "historical_source", "frequency"),
        ("T1", "historical_source", "timeframe"),
        ("T2", "temporal", "frequency"),
        ("T2", "temporal", "timeframe"),
    ]


def test_temporal_matched_group_branches_are_separate_paths():
    from internal.conditions import resolve_temporal_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    for node_id in ("A", "B"):
        graph.add_node(
            node_id,
            conditions=[{"tag": "match", "value": node_id.lower()}],
            temporal_conditions=[],
        )
        graph.add_edge("0", node_id, relation_type="root")

    graph.add_node(
        "T",
        conditions=[],
        temporal_conditions=[
            {"tag": "frequency", "value": "2"},
            {"tag": "timeframe", "value": "30"},
            {"tag": "if_matched_group", "value": "source_group"},
        ],
    )
    for node_id in ("A", "B"):
        graph.add_edge(
            node_id,
            "T",
            relation_type="if_matched_group",
            selector="source_group",
        )

    paths = resolve_temporal_paths(graph, "T")

    assert [path["nodes"] for path in paths] == [
        ["0", "A", "T"],
        ["0", "B", "T"],
    ]
    assert {
        path["edges"][-1]["selector"]
        for path in paths
    } == {"source_group"}
    assert all(
        path["conditions"][0]["scope"] == "historical_source"
        for path in paths
    )


def test_flattened_conditions_omit_all_relationship_selectors():
    from internal.conditions import (
        resolve_atomic_paths,
        resolve_temporal_paths,
    )

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    graph.add_node(
        "A",
        conditions=[{"tag": "match", "value": "source"}],
        temporal_conditions=[],
    )
    graph.add_node(
        "B",
        conditions=[
            {"tag": "if_sid", "value": "A"},
            {"tag": "if_group", "value": "source_group"},
            {"tag": "field", "value": "current"},
        ],
        temporal_conditions=[],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid", selector="A")

    atomic = resolve_atomic_paths(graph, "B")[0]
    assert [row["tag"] for row in atomic["conditions"]] == [
        "match",
        "field",
    ]

    graph.add_node(
        "T",
        conditions=[],
        temporal_conditions=[
            {"tag": "frequency", "value": "2"},
            {"tag": "timeframe", "value": "30"},
            {"tag": "if_matched_sid", "value": "B"},
            {"tag": "if_matched_group", "value": "source_group"},
        ],
    )
    graph.add_edge(
        "B",
        "T",
        relation_type="if_matched_sid",
        selector="B",
    )

    temporal = resolve_temporal_paths(graph, "T")[0]
    assert [row["tag"] for row in temporal["conditions"]] == [
        "match",
        "field",
        "frequency",
        "timeframe",
    ]



def _field_condition(
    name: str,
    value: str,
    **attributes: str,
) -> dict[str, object]:
    return {
        "tag": "field",
        "value": value,
        "attributes": {"name": name, **attributes},
    }


def test_narrower_child_field_subsumes_parent_condition():
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[
            _field_condition(
                "user",
                "^root$|^admin$|^administrator$",
            )
        ],
    )
    graph.add_node(
        "B",
        conditions=[_field_condition("user", "^admin$")],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")

    rows = resolve_atomic_paths(graph, "B")[0]["conditions"]

    assert rows[0]["resolution_status"] == "subsumed"
    assert rows[0]["resolution_note"] == "Subsumed by rule B"
    assert "resolution_status" not in rows[1]


def test_broader_child_field_is_redundant():
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[_field_condition("user", "^admin$")],
    )
    graph.add_node(
        "B",
        conditions=[
            _field_condition(
                "user",
                "^root$|^admin$|^administrator$",
            )
        ],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")

    rows = resolve_atomic_paths(graph, "B")[0]["conditions"]

    assert "resolution_status" not in rows[0]
    assert rows[1]["resolution_status"] == "redundant"


def test_partial_same_field_overlap_is_not_simplified():
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[_field_condition("user", "^root$|^admin$")],
    )
    graph.add_node(
        "B",
        conditions=[
            _field_condition("user", "^admin$|^administrator$")
        ],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")

    rows = resolve_atomic_paths(graph, "B")[0]["conditions"]

    assert all("resolution_status" not in row for row in rows)


def test_disjoint_same_field_constraints_are_contradictory():
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[_field_condition("user", "^root$")],
    )
    graph.add_node(
        "B",
        conditions=[_field_condition("user", "^admin$")],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")

    rows = resolve_atomic_paths(graph, "B")[0]["conditions"]

    assert rows[1]["resolution_status"] == "contradiction"
    assert rows[1]["resolution_note"] == (
        "Contradicts prior constraints on user"
    )


@pytest.mark.parametrize(
    "parent,child,attributes",
    [
        ("^adm.*$", "^admin$", {}),
        ("^admin$", "^admin$", {"negate": "yes"}),
        ("^\\d+$", "^123$", {}),
    ],
)
def test_unproven_regex_relationships_are_left_unchanged(
    parent, child, attributes
):
    from internal.conditions import resolve_atomic_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[])
    graph.add_node(
        "A",
        conditions=[_field_condition("user", parent, **attributes)],
    )
    graph.add_node(
        "B",
        conditions=[_field_condition("user", child)],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")

    rows = resolve_atomic_paths(graph, "B")[0]["conditions"]

    assert all("resolution_status" not in row for row in rows)


def test_temporal_field_simplification_does_not_cross_scope():
    from internal.conditions import resolve_temporal_paths

    graph = nx.MultiDiGraph()
    graph.add_node("0", conditions=[], temporal_conditions=[])
    graph.add_node(
        "A",
        conditions=[
            _field_condition(
                "user",
                "^root$|^admin$|^administrator$",
            )
        ],
        temporal_conditions=[],
    )
    graph.add_node(
        "T",
        conditions=[_field_condition("user", "^admin$")],
        temporal_conditions=[{"tag": "frequency", "value": "2"}],
    )
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "T", relation_type="if_matched_sid")

    rows = resolve_temporal_paths(graph, "T")[0]["conditions"]
    user_rows = [row for row in rows if row["tag"] == "field"]

    assert [row["scope"] for row in user_rows] == [
        "historical_source",
        "current_event",
    ]
    assert all(
        "resolution_status" not in row
        for row in user_rows
    )
