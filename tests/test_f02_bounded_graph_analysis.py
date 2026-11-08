"""Exhaustive graph analysis must have deterministic output budgets."""
import networkx as nx

from internal.analyzer import Analyzer
from internal.conditions import enumerate_paths


def test_cycle_analysis_returns_bounded_sample():
    graph = nx.MultiDiGraph()
    graph.add_edges_from((str(a), str(b))
                         for a in range(6) for b in range(6) if a != b)
    analyzer = object.__new__(Analyzer)
    analyzer.G = graph

    result = analyzer.calculate_statistics(max_cycles=3)

    assert result["cycles_truncated"] is True
    assert len(result["cycles"]) <= 3


def test_path_enumeration_stops_after_explicit_budget():
    graph = nx.MultiDiGraph()
    graph.add_edges_from([("0", "A"), ("0", "B"),
                          ("A", "T"), ("B", "T")],
                         relation_type="if_sid")
    paths = enumerate_paths(graph, "T", max_paths=1)

    assert len(paths) == 1
    assert paths.truncated is True


def test_self_loop_edges_are_excluded_before_cycle_enumeration(monkeypatch):
    graph = nx.MultiDiGraph()
    graph.add_edges_from([
        ("A", "A"), ("A", "B"), ("B", "A"),
        ("B", "C"), ("C", "B"),
    ])
    analyzer = object.__new__(Analyzer)
    analyzer.G = graph
    original = nx.simple_cycles

    def guarded_cycles(candidate):
        assert "A" in candidate.nodes
        assert not candidate.has_edge("A", "A")
        return original(candidate)

    monkeypatch.setattr("internal.analyzer.simple_cycles", guarded_cycles)
    result = analyzer.calculate_statistics(max_cycles=2)

    assert result["self_loops"] == [{"id": "A"}]
    assert any(set(cycle[:-1]) == {"A", "B"} for cycle in result["cycles"])
    assert any(set(cycle[:-1]) == {"B", "C"} for cycle in result["cycles"])


def test_self_loop_and_multi_node_cycle_both_survive():
    graph = nx.MultiDiGraph()
    graph.add_edges_from([("A", "A"), ("A", "B"), ("B", "A")])
    analyzer = object.__new__(Analyzer)
    analyzer.G = graph
    result = analyzer.calculate_statistics(max_cycles=10)

    assert result["self_loops"] == [{"id": "A"}]
    assert any(set(cycle[:-1]) == {"A", "B"} for cycle in result["cycles"])
    assert result["cycles_truncated"] is False


def test_path_depth_budget_reports_incomplete_results():
    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [("0", "A"), ("A", "B"), ("B", "C"), ("C", "D")],
        relation_type="if_sid",
    )
    paths = enumerate_paths(graph, "D", max_depth=3)
    assert not paths
    assert paths.truncated is True


def test_path_budget_does_not_count_visited_self_loop_as_missing_path():
    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [("0", "A"), ("A", "A")], relation_type="if_sid"
    )

    paths = enumerate_paths(graph, "A", max_paths=1)

    assert [path["nodes"] for path in paths] == [["0", "A"]]
    assert paths.truncated is False


def test_stats_panel_discloses_truncated_cycle_samples():
    from pathlib import Path

    javascript = (
        Path(__file__).resolve().parents[1]
        / "src/internal/static/graph.js"
    ).read_text(encoding="utf-8")

    assert "stats.cycles_truncated" in javascript
    assert "Additional cycles omitted" in javascript


def test_direct_rule_counts_do_not_inflate_parallel_relationships():
    graph = nx.MultiDiGraph()
    graph.add_edge("0", "A", relation_type="root")
    graph.add_edge("A", "B", relation_type="if_sid")
    graph.add_edge("A", "B", relation_type="if_group")
    graph.add_edge("B", "C", relation_type="if_sid")
    analyzer = object.__new__(Analyzer)
    analyzer.G = graph
    stats = analyzer.calculate_statistics()
    descendants = {
        item["id"]: item["count"]
        for item in stats["top_direct_descendants"]
    }
    ancestors = {
        item["id"]: item["count"]
        for item in stats["top_direct_ancestors"]
    }
    assert descendants["A"] == 1
    assert descendants["B"] == 1
    assert ancestors["B"] == 1
    assert ancestors["C"] == 1
    assert stats["top_indirect_descendants"][0]["id"] == "A"
    assert stats["top_indirect_descendants"][0]["count"] == 2
