from internal.assessment import AssessmentClassifier, BitsetAssessor
from internal.assessment_report import (
    assessment_report_to_dict,
    build_assessment_report,
    write_assessment_report,
)
from internal.catalog import RuleCatalog
from internal.domains import BitsetDomain
from internal.evaluation import EvaluationBuilder


def add_rule(
    catalog,
    rule_id,
    level,
    *,
    if_sid=None,
    if_level=None,
    if_group=None,
    category=None,
    runtime_group="test,",
    accuracy=1,
    noalert=False,
    overwrite=False,
):
    catalog.append(
        rule_id=str(rule_id),
        file="test.xml",
        source_level=level,
        accuracy=accuracy,
        noalert=noalert,
        overwrite=overwrite,
        runtime_group=runtime_group,
        display_groups=[],
        category=category,
        if_sid=if_sid,
        if_level=if_level,
        if_group=if_group,
        if_matched_sid=None,
        if_matched_group=None,
        conditions=[],
        temporal_conditions=[],
    )


def make_report(catalog, event_count, predicates):
    model = EvaluationBuilder(catalog).build()
    domain = BitsetDomain(event_count)
    result = BitsetAssessor(model, domain, predicates).assess()
    findings = AssessmentClassifier(model, result).classify()
    return build_assessment_report(
        model,
        domain,
        result,
        findings,
    )


def test_report_aggregates_rule_occurrences_without_double_counting():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 5, category="a")
    add_rule(catalog, 2, 5, category="b")
    add_rule(catalog, 100200, 7, if_level=1)

    report = make_report(
        catalog,
        2,
        {
            "1": 0b11,
            "2": 0b11,
            "100200": 0b01,
        },
    )

    target = next(
        rule for rule in report.rules if rule.rule_id == "100200"
    )

    assert report.schema_version == 1
    assert report.event_count == 2
    assert target.occurrence_count == 2
    assert target.candidate_events == 1
    assert target.matched_events == 1
    assert target.selected_events == 1


def test_report_exposes_load_issues_without_evaluator_state():
    catalog = RuleCatalog()
    add_rule(catalog, 100201, 5, category="missing")

    report = make_report(catalog, 1, {"100201": 1})

    assert report.rules == ()
    assert [
        (issue.code, issue.rule_id, issue.selector)
        for issue in report.issues
    ] == [
        ("CATEGORY_NOT_FOUND", "100201", "missing")
    ]


def test_report_serialization_is_deterministic_and_uses_counts(tmp_path):
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100210, 10, if_sid="1")
    add_rule(catalog, 100211, 5, if_sid="1")

    report = make_report(
        catalog,
        2,
        {
            "1": 0b11,
            "100210": 0b01,
            "100211": 0b11,
        },
    )

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_assessment_report(report, first)
    write_assessment_report(report, second)

    assert first.read_bytes() == second.read_bytes()

    payload = assessment_report_to_dict(report)
    target = next(
        rule
        for rule in payload["rules"]
        if rule["rule_id"] == "100211"
    )

    assert target["shadowed_events"] == 1
    assert target["findings"][0]["kind"] == "partially_shadowed"
    assert "region" not in target["findings"][0]


def _rule(report, rule_id):
    return next(rule for rule in report.rules if rule.rule_id == rule_id)


def _kinds(report, rule_id):
    return [finding.kind.value for finding in _rule(report, rule_id).findings]


def test_end_to_end_finding_classification_matrix():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100220, 12, if_sid="1")
    add_rule(catalog, 100221, 10, if_sid="1")
    add_rule(catalog, 100222, 8, if_sid="1")
    add_rule(catalog, 100223, 0, if_sid="1")

    report = make_report(
        catalog,
        4,
        {
            "1": 0b1111,
            "100220": 0b0001,
            "100221": 0b0011,
            "100222": 0b0001,
            "100223": 0b1000,
        },
    )

    assert _kinds(report, "100220") == []
    assert _kinds(report, "100221") == ["partially_shadowed"]
    assert _kinds(report, "100222") == ["fully_shadowed"]
    assert _kinds(report, "100223") == ["dropped"]


def test_end_to_end_noalert_gate_and_fallthrough():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100230, 12, if_sid="1", noalert=True)
    add_rule(catalog, 100231, 13, if_sid="100230")
    add_rule(catalog, 100232, 5, if_sid="1")

    report = make_report(
        catalog,
        2,
        {
            "1": 0b11,
            "100230": 0b11,
            "100231": 0b01,
            "100232": 0b11,
        },
    )

    gate = _rule(report, "100230")
    child = _rule(report, "100231")
    sibling = _rule(report, "100232")

    assert _kinds(report, "100230") == ["never_selected"]
    assert gate.matched_events == 2
    assert gate.selected_events == 0
    assert child.selected_events == 1
    assert sibling.selected_events == 1


def test_end_to_end_missing_parent_is_reported_and_excluded():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100240, 5, if_sid="999999")

    report = make_report(
        catalog,
        1,
        {"1": 1, "100240": 1},
    )

    assert all(rule.rule_id != "100240" for rule in report.rules)
    assert [
        (issue.code, issue.rule_id, issue.selector)
        for issue in report.issues
    ] == [("SID_NOT_FOUND", "100240", "999999")]


def test_end_to_end_overwrite_order_affects_shadowing():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100250, 10, if_sid="1")
    add_rule(catalog, 100251, 5, if_sid="1")
    add_rule(catalog, 100250, 1, overwrite=True)
    add_rule(catalog, 100252, 7, if_sid="1")

    report = make_report(
        catalog,
        2,
        {
            "1": 0b11,
            "100250": 0b01,
            "100251": 0b01,
            "100252": 0b01,
        },
    )

    assert _rule(report, "100252").selected_events == 1
    assert _kinds(report, "100250") == ["fully_shadowed"]
    assert _kinds(report, "100251") == ["fully_shadowed"]


def test_end_to_end_multiple_occurrences_remain_logical_rule_aggregate():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 5, category="a")
    add_rule(catalog, 2, 5, category="b")
    add_rule(catalog, 100260, 7, if_level=1)

    report = make_report(
        catalog,
        3,
        {
            "1": 0b111,
            "2": 0b111,
            "100260": 0b011,
        },
    )

    target = _rule(report, "100260")
    assert target.occurrence_count == 2
    assert target.candidate_events == 2
    assert target.selected_events == 2


def test_end_to_end_report_handles_deep_chain():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")

    parent = "1"
    for index in range(500):
        rule_id = str(300000 + index)
        add_rule(catalog, rule_id, 5, if_sid=parent)
        parent = rule_id

    report = make_report(catalog, 1, {"1": 1})

    deepest = _rule(report, parent)
    assert deepest.selected_events == 1
    assert deepest.occurrence_count == 1
