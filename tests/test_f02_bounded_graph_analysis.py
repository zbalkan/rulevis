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
