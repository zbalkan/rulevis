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
            {
                "tag": "field",
                "value": "^deny$",
                "attributes": {"name": "event.action"},
            }
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
        ("T", "temporal", "if_matched_sid"),
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
