"""Structural resource diagnostics do not require event-domain assessment."""
from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder
from internal.assessment_report import build_resource_report, resource_report_to_dict


def test_resource_report_counts_occurrences_not_logical_rules():
    catalog = RuleCatalog()
    for rule_id, sid in [("1", None), ("100100", "1"), ("100101", "1")]:
        catalog.append(rule_id=rule_id, file="rules.xml", source_level=3,
                       accuracy=1, noalert=False, overwrite=False,
                       runtime_group="test,", display_groups=[],
                       category="syslog", if_sid=sid, if_level=None,
                       if_group=None, if_matched_sid=None,
                       if_matched_group=None, conditions=[],
                       temporal_conditions=[])
    model = EvaluationBuilder(catalog).build()
    report = resource_report_to_dict(build_resource_report(model, node_size=32))

    assert report["total_occurrences"] == 3
    assert report["estimated_node_bytes"] == 96
    assert report["occurrences_by_rule"]["1"] == 1
    assert report["occurrences_by_rule"]["100100"] == 1
    assert report["occurrences_by_rule"]["100101"] == 1
