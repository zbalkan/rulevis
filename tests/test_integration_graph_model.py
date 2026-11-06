"""Integration guard: compose group resolution and dual occurrence budgets."""
import pytest

from internal.evaluation import (
    EvaluationBuilder,
    OccurrenceBudgetExceeded,
    RuleTreeLimitExceeded,
)
from internal.generator import GraphGenerator


def test_group_runtime_fidelity_and_limit_boundaries(tmp_path):
    path = tmp_path / "rules.xml"
    path.write_text(
        '<group name="auth_failed,">'
        '<rule id="1" level="0"><description>Root</description></rule>'
        '<rule id="100100" level="3"><if_group>auth</if_group>'
        '<description>First</description></rule>'
        '<rule id="100101" level="3"><if_group>auth</if_group>'
        '<description>Second</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    generator.build_graph_from_xml()
    graph = generator.G

    assert graph.has_edge("1", "100100")
    assert graph.has_edge("100100", "100101")
    assert not graph.has_edge("100101", "100100")
    assert not graph.has_edge("100100", "100100")

    model = EvaluationBuilder(
        generator.catalog, node_limit=4, max_occurrences=4
    ).build()
    assert len(model.occurrences) == 4

    with pytest.raises(RuleTreeLimitExceeded) as rejected:
        EvaluationBuilder(
            generator.catalog, node_limit=3, max_occurrences=4
        ).build()
    assert rejected.value.node_count == 3
    assert rejected.value.rule_id == "100101"

    with pytest.raises(OccurrenceBudgetExceeded) as exhausted:
        EvaluationBuilder(
            generator.catalog, node_limit=4, max_occurrences=3
        ).build()
    assert exhausted.value.node_count == 3
    assert exhausted.value.rule_id == "100101"
