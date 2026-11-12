"""Modeled occurrence-forest / SID quotient contract (not native verification)."""

import networkx as nx

from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder, project_occurrence_relationships


def _rule(catalog, sid, *, if_sid=None):
    catalog.append(
        rule_id=str(sid),
        file="quotient.xml",
        source_level=0 if sid == 1 else 5,
        accuracy=1,
        noalert=False,
        overwrite=False,
        runtime_group="test,",
        display_groups=[],
        category="syslog",
        if_sid=if_sid,
        if_level=None,
        if_group=None,
        if_matched_sid=None,
        if_matched_group=None,
        conditions=[],
        temporal_conditions=[],
    )


def test_incremental_self_sid_is_acyclic_physically_but_loops_in_quotient():
    catalog = RuleCatalog()
    _rule(catalog, 1)
    _rule(catalog, 100101, if_sid="1,100101")

    model = EvaluationBuilder(catalog).build()
    graph = project_occurrence_relationships(model)

    assert nx.is_directed_acyclic_graph(model.graph)
    assert len(model.occurrences_by_rule["100101"]) == 2
    first, second = model.occurrences_by_rule["100101"]
    assert model.occurrences[first].parent_id == model.occurrences_by_rule["1"][0]
    assert model.occurrences[second].parent_id == first
    assert graph.has_edge("100101", "100101")
    assert graph.nodes["100101"]["occurrence_count"] == 2
    assert not nx.is_directed_acyclic_graph(graph)


def test_quotient_collapses_repeated_sid_occurrences_but_counts_attachments():
    catalog = RuleCatalog()
    _rule(catalog, 1)
    _rule(catalog, 100101, if_sid="1,1")

    model = EvaluationBuilder(catalog).build()
    graph = project_occurrence_relationships(model)

    assert nx.is_directed_acyclic_graph(model.graph)
    assert len(model.occurrences_by_rule["100101"]) == 2
    assert sum(
        attrs["occurrence_count"]
        for attrs in graph.get_edge_data("1", "100101").values()
    ) == 2
    assert graph.nodes["100101"]["occurrence_count"] == 2
