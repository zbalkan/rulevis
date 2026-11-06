"""Exact Wazuh PR #40182 threshold semantics on runtime occurrences."""
import pytest
from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder, RuleTreeLimitExceeded


def make_catalog():
    catalog = RuleCatalog()
    for rule_id, sid in [("1", None), ("100100", "1"),
                         ("100101", "1"), ("100102", "1")]:
        catalog.append(rule_id=rule_id, file="rules.xml",
                       source_level=0 if sid is None else 3,
                       accuracy=1, noalert=False, overwrite=False,
                       runtime_group="test,", display_groups=[],
                       category="syslog", if_sid=sid, if_level=None,
                       if_group=None, if_matched_sid=None,
                       if_matched_group=None, conditions=[],
                       temporal_conditions=[])
    return catalog


def test_limit_refuses_node_after_allowed_boundary():
    builder = EvaluationBuilder(make_catalog(), node_warning=2, node_limit=3)
    with pytest.raises(RuleTreeLimitExceeded) as caught:
        builder.build()
    assert caught.value.node_count == 3
    assert caught.value.rule_id == "100102"
    assert caught.value.rule_node_count == 0
    assert builder.warning_rule_id == "100101"


def test_exact_limit_is_accepted():
    model = EvaluationBuilder(make_catalog(), node_limit=4).build()
    assert len(model.occurrences) == 4
