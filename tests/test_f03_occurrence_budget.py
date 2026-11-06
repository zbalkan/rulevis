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


def test_group_attachment_does_not_sort_all_candidate_occurrences(monkeypatch):
    import internal.evaluation as evaluation

    catalog = RuleCatalog()
    for rule_id, selector in [
        ("1", None), ("100100", "loop"), ("100101", "loop"),
    ]:
        catalog.append(
            rule_id=rule_id, file="test.xml",
            source_level=0 if selector is None else 3,
            accuracy=1, noalert=False, overwrite=False,
            runtime_group="loop,", display_groups=[], category="syslog",
            if_sid=None, if_level=None, if_group=selector,
            if_matched_sid=None, if_matched_group=None,
            conditions=[], temporal_conditions=[],
        )

    def forbid_full_sort(*args, **kwargs):
        raise AssertionError("group candidate collection must be bounded")

    monkeypatch.setattr(evaluation, "sorted", forbid_full_sort, raising=False)
    model = EvaluationBuilder(catalog, max_occurrences=4).build()
    assert len(model.occurrences) == 4


def test_if_level_does_not_build_unbounded_preorder_list(monkeypatch):
    catalog = RuleCatalog()
    for rule_id, if_level in [
        ("1", None), ("100100", 3), ("100101", 3),
    ]:
        catalog.append(
            rule_id=rule_id, file="test.xml",
            source_level=0 if if_level is None else 3,
            accuracy=1, noalert=False, overwrite=False,
            runtime_group="test,", display_groups=[], category="syslog",
            if_sid=None, if_level=if_level, if_group=None,
            if_matched_sid=None, if_matched_group=None,
            conditions=[], temporal_conditions=[],
        )

    def forbidden_snapshot(self):
        raise AssertionError("if_level must not snapshot the entire tree")

    monkeypatch.setattr(
        EvaluationBuilder, "_occurrences_in_preorder", forbidden_snapshot
    )
    model = EvaluationBuilder(catalog, max_occurrences=4).build()
    assert len(model.occurrences) == 4


@pytest.mark.parametrize(
    "invalid_budget",
    [True, False, 2.0, 0.5, float("nan"), float("inf"), "3", None],
)
def test_occurrence_budget_rejects_non_integer_inputs(invalid_budget):
    with pytest.raises(ValueError, match="positive integer"):
        EvaluationBuilder(
            catalog_with_children(1), max_occurrences=invalid_budget
        )
