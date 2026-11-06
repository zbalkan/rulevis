"""Bound RuleVis's Python occurrence allocations independent of Wazuh."""
import pytest
from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder, OccurrenceBudgetExceeded


def catalog_with_children(count):
    catalog = RuleCatalog()
    catalog.append(rule_id="1", file="test.xml", source_level=0,
                   accuracy=1, noalert=False, overwrite=False,
                   runtime_group="test,", display_groups=[], category="syslog",
                   if_sid=None, if_level=None, if_group=None,
                   if_matched_sid=None, if_matched_group=None,
                   conditions=[], temporal_conditions=[])
    for index in range(count):
        catalog.append(rule_id=str(100100 + index), file="test.xml",
                       source_level=3, accuracy=1, noalert=False,
                       overwrite=False, runtime_group="test,",
                       display_groups=[], category="syslog", if_sid="1",
                       if_level=None, if_group=None, if_matched_sid=None,
                       if_matched_group=None, conditions=[],
                       temporal_conditions=[])
    return catalog


def test_occurrence_budget_rejects_next_allocation():
    builder = EvaluationBuilder(catalog_with_children(5), max_occurrences=3)
    with pytest.raises(OccurrenceBudgetExceeded) as captured:
        builder.build()
    assert captured.value.limit == 3
    assert captured.value.node_count == 3
    assert captured.value.rule_id == "100102"


def test_occurrence_budget_allows_exact_boundary():
    model = EvaluationBuilder(catalog_with_children(2), max_occurrences=3).build()
    assert len(model.occurrences) == 3


def test_occurrence_budget_must_be_positive():
    with pytest.raises(ValueError):
        EvaluationBuilder(catalog_with_children(1), max_occurrences=0)
