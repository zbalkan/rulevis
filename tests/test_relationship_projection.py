import networkx as nx

from internal.catalog import RuleCatalog
from internal.evaluation import (
    EvaluationBuilder,
    project_occurrence_relationships,
)
from internal.generator import GraphGenerator


def _append(
    catalog, rule_id, level, *, group="audit_watch_write,",
    category="syslog", overwrite=False, if_sid=None, if_group=None,
    if_level=None,
):
    catalog.append(
        rule_id=str(rule_id), file="fixture.xml", source_level=level,
        accuracy=1, noalert=False, overwrite=overwrite,
        runtime_group=group, display_groups=[], category=category,
        if_sid=if_sid, if_level=if_level, if_group=if_group,
        if_matched_sid=None, if_matched_group=None,
        conditions=[], temporal_conditions=[],
    )


def _edges(graph, parent, child, relation):
    return [
        data
        for data in (graph.get_edge_data(parent, child) or {}).values()
        if data["relation_type"] == relation
    ]


def test_source_cycle_and_runtime_occurrences_are_distinct(tmp_path):
    (tmp_path / "rules.xml").write_text(
        '<group name="audit_watch_write,">'
        '<rule id="1" level="0"><description>Root</description></rule>'
        '<rule id="80790" level="3"><if_group>audit_watch_write</if_group>'
        '<description>Created</description></rule>'
        '<rule id="80791" level="3"><if_group>audit_watch_write</if_group>'
        '<description>Deleted</description></rule></group>',
        encoding="utf-8",
    )
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pkl"))
    generator.build_graph_from_xml()

    declared = generator.G
    model = EvaluationBuilder(generator.catalog).build()
    runtime = project_occurrence_relationships(model)

    assert _edges(declared, "80790", "80791", "if_group")
    assert _edges(declared, "80791", "80790", "if_group")
    assert not nx.is_directed_acyclic_graph(declared)
    assert _edges(runtime, "80790", "80791", "if_group")
    assert not _edges(runtime, "80791", "80790", "if_group")
    assert nx.is_directed_acyclic_graph(model.graph)
    assert model.rules["80791"].parent_relation == "if_group"
    assert model.occurrences_by_rule["80791"]


def test_projection_preserves_multiplicity_and_if_level_relation():
    catalog = RuleCatalog()
    _append(catalog, 1, 0, group="root,")
    _append(catalog, 2, 0, group="root,")
    _append(catalog, 100841, 9, if_level=8, group="level,")
    _append(catalog, 100842, 10, if_sid="100841", group="child,")
    model = EvaluationBuilder(catalog).build()
    runtime = project_occurrence_relationships(model)

    assert model.rules["100841"].parent_relation == "if_level"
    assert model.rules["100841"].parent_selector == "8"
    assert len(model.occurrences_by_rule["100841"]) == 2
    assert len(model.occurrences_by_rule["100842"]) == 2
    assert _edges(runtime, "1", "100841", "if_level")
    assert _edges(runtime, "2", "100841", "if_level")
    sid = _edges(runtime, "100841", "100842", "if_sid")
    assert len(sid) == 1
    assert sid[0]["occurrence_count"] == 2


def test_projection_excludes_rejected_duplicate_after_missing_base_overwrite():
    catalog = RuleCatalog()
    _append(catalog, 1, 0, group="root,")
    _append(catalog, 100850, 4, group="early,", overwrite=True)
    _append(catalog, 100850, 12, group="later,")
    _append(catalog, 100851, 5, group="child,", if_sid="100850")

    model = EvaluationBuilder(catalog).build()
    runtime = project_occurrence_relationships(model)

    assert model.rules["100850"].runtime_group == "early,"
    assert any(
        issue.code == "OVERWRITE_RULE_NOT_FOUND"
        for issue in model.issues
    )
    assert any(
        issue.code == "DUPLICATE_RULE_ID"
        for issue in model.issues
    )
    assert _edges(runtime, "100850", "100851", "if_sid")


def test_projection_retains_structural_type_and_temporal_origin():
    catalog = RuleCatalog()
    _append(catalog, 1, 0, group="root,")
    _append(catalog, 100861, 5, group="auth,", if_sid="1")

    catalog.append(
        rule_id="100862", file="fixture.xml", source_level=8,
        accuracy=1, noalert=False, overwrite=False,
        runtime_group="child,", display_groups=[], category="syslog",
        if_sid=None, if_level=None, if_group=None,
        if_matched_sid=100861, if_matched_group=None,
        conditions=[], temporal_conditions=[],
    )
    catalog.append(
        rule_id="100863", file="fixture.xml", source_level=8,
        accuracy=1, noalert=False, overwrite=False,
        runtime_group="child,", display_groups=[], category="syslog",
        if_sid=None, if_level=None, if_group=None,
        if_matched_sid=None, if_matched_group="auth",
        conditions=[], temporal_conditions=[],
    )

    model = EvaluationBuilder(catalog).build()
    runtime = project_occurrence_relationships(model)

    sid = _edges(runtime, "100861", "100862", "if_sid")
    group = _edges(runtime, "100861", "100863", "if_group")

    assert len(sid) == 1
    assert sid[0]["synthesized_from"] == "if_matched_sid"
    assert len(group) == 1
    assert group[0]["synthesized_from"] == "if_matched_group"
    assert not _edges(runtime, "100861", "100862", "if_matched_sid")
    assert not _edges(runtime, "100861", "100863", "if_matched_group")


def test_multi_sid_projection_records_matching_parent_selector():
    catalog = RuleCatalog()
    _append(catalog, 1, 0, group="root,")
    _append(catalog, 2, 0, group="root,")
    _append(catalog, 100870, 7, if_sid="000001,2", group="child,")

    model = EvaluationBuilder(catalog).build()
    projected = project_occurrence_relationships(model)

    first = _edges(projected, "1", "100870", "if_sid")
    second = _edges(projected, "2", "100870", "if_sid")
    assert len(first) == 1
    assert len(second) == 1
    assert first[0]["selector"] == "000001"
    assert second[0]["selector"] == "2"


def test_repeated_sid_textual_references_preserve_distinct_provenance():
    catalog = RuleCatalog()
    _append(catalog, 1, 0, group="root,")
    _append(catalog, 100871, 7, if_sid="1,000001", group="child,")

    model = EvaluationBuilder(catalog).build()
    projected = project_occurrence_relationships(model)
    sid = _edges(projected, "1", "100871", "if_sid")

    assert len(model.occurrences_by_rule["100871"]) == 2
    assert {edge["selector"] for edge in sid} == {"1", "000001"}
    assert all(edge["occurrence_count"] == 1 for edge in sid)
