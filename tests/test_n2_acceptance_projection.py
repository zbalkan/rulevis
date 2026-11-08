"""N2 contract: declared provenance must not imply modeled acceptance.

Red-phase specifications. The source graph remains source-faithful; a distinct
occurrence-derived projection carries modeled attachments and their counts.
Wazuh 4.14.10 differential fixtures are required before claiming runtime parity.
"""
import pytest

from internal.evaluation import EvaluationBuilder, project_occurrence_relationships
from internal.generator import GraphGenerator


def make_generator(tmp_path, body):
    (tmp_path / "rules.xml").write_text(body, encoding="utf-8")
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()
    return generator


def modeled_edge_tuples(graph):
    return {
        (source, target, data["relation_type"])
        for source, target, data in graph.edges(data=True)
    }


@pytest.mark.parametrize(
    "body,rejected,dependent,relation",
    [
        (
            '<group name="root,">'
            '<rule id="1" level="5"><description>Root</description></rule>'
            '</group><group name="rejected_source,">'
            '<rule id="100101" level="12"><if_sid>999999</if_sid>'
            '<description>Missing parent</description></rule></group>'
            '<group name="child,">'
            '<rule id="100102" level="7"><if_group>rejected_source</if_group>'
            '<description>Group child</description></rule></group>',
            "100101", "100102", "if_group",
        ),
        (
            '<group name="root,">'
            '<rule id="1" level="5"><description>Root</description></rule>'
            '<rule id="100101" level="12"><if_sid>999999</if_sid>'
            '<description>Missing parent</description></rule>'
            '<rule id="100102" level="7"><if_level>10</if_level>'
            '<description>Level child</description></rule></group>',
            "100101", "100102", "if_level",
        ),
        (
            '<group name="root,">'
            '<rule id="1" level="5"><description>Root</description></rule>'
            '<rule id="100102" level="7"><if_sid>100101</if_sid>'
            '<description>Premature child</description></rule>'
            '<rule id="100101" level="12"><if_sid>1</if_sid>'
            '<description>Later parent</description></rule></group>',
            "100102", "100102", "if_sid",
        ),
    ],
)
def test_rejected_or_future_parent_keeps_declaration_but_not_effective_edge(
    tmp_path, body, rejected, dependent, relation
):
    generator = make_generator(tmp_path, body)
    assert any(
        target == dependent and data["relation_type"] == relation
        for _, target, data in generator.G.edges(data=True)
    )

    # Existing evaluator provides an independent baseline for the intended
    # model; it does not claim validation against a running Wazuh loader.
    expected = project_occurrence_relationships(
        EvaluationBuilder(generator.catalog).build()
    )
    assert dependent not in expected

    # New N2 API must never mistake the source declaration for an accepted
    # attachment. In the future, the two projections remain independently
    # inspectable rather than deleting rejected source edges.
    actual = generator.modeled_runtime_graph
    assert dependent not in actual
    assert rejected not in actual if rejected != dependent else True
    assert all(
        target != dependent for _, target, _ in modeled_edge_tuples(actual)
    )
    assert generator.G.nodes[dependent]["modeled_acceptance"] == "rejected"


def test_valid_parent_chain_has_effective_edges_with_occurrence_provenance(
    tmp_path,
):
    generator = make_generator(
        tmp_path,
        '<group name="root,">'
        '<rule id="1" level="5"><description>Root</description></rule>'
        '<rule id="100120" level="7"><if_sid>1</if_sid>'
        '<description>Child</description></rule>'
        '<rule id="100121" level="8"><if_sid>100120</if_sid>'
        '<description>Grandchild</description></rule></group>',
    )
    actual = generator.modeled_runtime_graph
    assert modeled_edge_tuples(actual) == {
        ("1", "100120", "if_sid"),
        ("100120", "100121", "if_sid"),
    }
    assert all(
        data["occurrence_count"] == 1
        for _, _, data in actual.edges(data=True)
    )
    assert generator.G.nodes["100120"]["modeled_acceptance"] == "accepted"
    assert generator.G.nodes["100121"]["modeled_acceptance"] == "accepted"


def test_if_level_fanout_preserves_distinct_physical_occurrences(tmp_path):
    generator = make_generator(
        tmp_path,
        '<group name="root,">'
        '<rule id="1" level="10"><description>First</description></rule>'
        '<rule id="2" level="10"><description>Second</description></rule>'
        '<rule id="100130" level="7"><if_level>5</if_level>'
        '<description>Fanout</description></rule></group>',
    )
    actual = generator.modeled_runtime_graph
    assert actual.nodes["100130"]["occurrence_count"] == 2
    parents = {
        source for source, target in actual.edges()
        if target == "100130"
    }
    assert parents == {"1", "2"}
    assert all(
        data["relation_type"] == "if_level"
        and data["occurrence_count"] == 1
        for source, target, data in actual.edges(data=True)
        if target == "100130"
    )
    assert generator.G.nodes["100130"]["modeled_acceptance"] == "accepted"
