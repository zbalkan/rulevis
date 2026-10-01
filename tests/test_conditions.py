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
