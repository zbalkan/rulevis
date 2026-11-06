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


def test_self_loop_nodes_are_excluded_before_cycle_enumeration(monkeypatch):
    graph = nx.MultiDiGraph()
    graph.add_edges_from([
        ("A", "A"), ("A", "B"), ("B", "A"),
        ("B", "C"), ("C", "B"),
    ])
    analyzer = object.__new__(Analyzer)
    analyzer.G = graph
    original = nx.simple_cycles

    def guarded_cycles(candidate):
        assert "A" not in candidate.nodes
        return original(candidate)

    monkeypatch.setattr("internal.analyzer.simple_cycles", guarded_cycles)
    result = analyzer.calculate_statistics(max_cycles=2)

    assert result["self_loops"] == [{"id": "A"}]
    assert result["cycles"] == [["B", "C", "B"]] or result["cycles"] == [["C", "B", "C"]]
