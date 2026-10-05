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
    category=None,
):
    catalog.append(
        rule_id=str(rule_id),
        file="test.xml",
        source_level=level,
        accuracy=1,
        noalert=False,
        overwrite=False,
        runtime_group="test,",
        display_groups=[],
        category=category,
        if_sid=if_sid,
        if_level=if_level,
        if_group=None,
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
