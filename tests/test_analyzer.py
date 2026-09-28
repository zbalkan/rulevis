import json
import pickle

import networkx as nx
import pytest

from internal.analyzer import Analyzer


def write_graph(tmp_path, graph):
    graph_path = tmp_path / "graph.pickle"
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    return graph_path


def test_missing_graph_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        Analyzer(str(tmp_path / "missing.pickle"))


def test_calculate_statistics_reports_structure_cycles_and_isolated_rules(
    tmp_path,
):
    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [
            ("0", "1"),
            ("1", "2"),
            ("2", "3"),
            ("3", "2"),
            ("0", "4"),
            ("0", "5"),
            ("5", "5"),
        ]
    )

    stats = Analyzer(str(write_graph(tmp_path, graph))).calculate_statistics()

    assert stats["isolated_rules"] == [{"id": "4"}]
    assert stats["self_loops"] == [{"id": "5"}]

    assert len(stats["cycles"]) == 1
    cycle = stats["cycles"][0]
    assert cycle[0] == cycle[-1]
    assert set(cycle[:-1]) == {"2", "3"}

    direct_descendants = {
        item["id"]: item["count"]
        for item in stats["top_direct_descendants"]
    }
    assert direct_descendants["1"] == 1
    assert direct_descendants["2"] == 1


def test_calculate_heatmap_data_counts_numeric_rule_ids(tmp_path):
    graph = nx.MultiDiGraph()
    graph.add_nodes_from(["0", "1", "9", "10", "25", "not-a-rule"])

    heatmap = Analyzer(
        str(write_graph(tmp_path, graph))
    ).calculate_heatmap_data(block_size=10)

    assert heatmap["metadata"] == {
        "block_size": 10,
        "max_id": 30,
        "total_blocks": 3,
    }
    assert heatmap["blocks"] == [
        {"id": "0-9", "count": 2},
        {"id": "10-19", "count": 1},
        {"id": "20-29", "count": 1},
    ]


def test_calculate_heatmap_data_handles_no_numeric_rules(tmp_path):
    graph = nx.MultiDiGraph()
    graph.add_nodes_from(["0", "virtual"])

    heatmap = Analyzer(
        str(write_graph(tmp_path, graph))
    ).calculate_heatmap_data(block_size=50)

    assert heatmap == {
        "metadata": {
            "block_size": 50,
            "max_id": 0,
            "total_blocks": 0,
        },
        "blocks": [],
    }


def test_write_to_json_writes_statistics_and_heatmap(tmp_path):
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "100")
    graph_path = write_graph(tmp_path, graph)
    stats_path = tmp_path / "stats.json"
    heatmap_path = tmp_path / "heatmap.json"

    Analyzer(str(graph_path)).write_to_json(
        str(stats_path),
        str(heatmap_path),
    )

    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    heatmap = json.loads(heatmap_path.read_text(encoding="utf-8"))

    assert "top_direct_descendants" in stats
    assert heatmap["metadata"]["block_size"] == 10
    assert heatmap["blocks"][-1] == {"id": "90-99", "count": 0} or heatmap["blocks"][-1] == {"id": "100-109", "count": 1}
