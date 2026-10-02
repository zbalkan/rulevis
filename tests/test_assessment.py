from internal.assessment import BitsetAssessor
from internal.catalog import RuleCatalog
from internal.domains import BitsetDomain
from internal.evaluation import EvaluationBuilder


def add_rule(
    catalog,
    rule_id,
    level,
    *,
    noalert=False,
    if_sid=None,
    category=None,
):
    catalog.append(
        rule_id=str(rule_id),
        file="test.xml",
        source_level=level,
        accuracy=1,
        noalert=noalert,
        overwrite=False,
        runtime_group="test,",
        display_groups=[],
        category=category,
        if_sid=if_sid,
        if_level=None,
        if_group=None,
        if_matched_sid=None,
        if_matched_group=None,
        conditions=[],
        temporal_conditions=[],
    )


def assess(catalog, event_count, predicates):
    model = EvaluationBuilder(catalog).build()
    result = BitsetAssessor(
        model,
        BitsetDomain(event_count),
        predicates,
    ).assess()
    return model, result


def test_earlier_sibling_fully_shadows_later_sibling():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100001, 10, if_sid="1")
    add_rule(catalog, 100002, 5, if_sid="1")

    model, result = assess(
        catalog,
        4,
        {
            "1": 0b1111,
            "100001": 0b0011,
            "100002": 0b0011,
        },
    )

    later = model.occurrences_by_rule["100002"][0]
    facts = result.facts[later]

    assert facts.candidate == 0b0011
    assert facts.matched == 0
    assert facts.shadowed == 0b0011


def test_child_selection_precedes_parent_selection():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100010, 10, if_sid="1")
    add_rule(catalog, 100011, 11, if_sid="100010")

    model, result = assess(
        catalog,
        4,
        {
            "1": 0b1111,
            "100010": 0b1111,
            "100011": 0b0011,
        },
    )

    parent = model.occurrences_by_rule["100010"][0]
    child = model.occurrences_by_rule["100011"][0]

    assert result.facts[child].selected == 0b0011
    assert result.facts[parent].selected == 0b1100


def test_noalert_without_returning_child_falls_through():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(
        catalog,
        100020,
        10,
        noalert=True,
        if_sid="1",
    )
    add_rule(catalog, 100021, 5, if_sid="1")

    model, result = assess(
        catalog,
        2,
        {
            "1": 0b11,
            "100020": 0b11,
            "100021": 0b11,
        },
    )

    gate = model.occurrences_by_rule["100020"][0]
    later = model.occurrences_by_rule["100021"][0]

    assert result.facts[gate].terminal == 0
    assert result.facts[later].selected == 0b11


def test_noalert_consumes_only_region_returned_by_descendant():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(
        catalog,
        100030,
        10,
        noalert=True,
        if_sid="1",
    )
    add_rule(catalog, 100031, 11, if_sid="100030")
    add_rule(catalog, 100032, 5, if_sid="1")

    model, result = assess(
        catalog,
        2,
        {
            "1": 0b11,
            "100030": 0b11,
            "100031": 0b01,
            "100032": 0b11,
        },
    )

    child = model.occurrences_by_rule["100031"][0]
    sibling = model.occurrences_by_rule["100032"][0]

    assert result.facts[child].selected == 0b01
    assert result.facts[sibling].selected == 0b10


def test_level_zero_is_terminal_but_dropped():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100040, 0, if_sid="1")
    add_rule(catalog, 100041, 5, if_sid="1")

    model, result = assess(
        catalog,
        2,
        {
            "1": 0b11,
            "100040": 0b01,
            "100041": 0b11,
        },
    )

    dropped = model.occurrences_by_rule["100040"][0]
    later = model.occurrences_by_rule["100041"][0]

    assert result.facts[dropped].dropped == 0b01
    assert result.facts[later].selected == 0b10


def test_deep_chain_does_not_depend_on_python_recursion():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")

    parent = "1"
    for index in range(2000):
        rule_id = str(200000 + index)
        add_rule(catalog, rule_id, 5, if_sid=parent)
        parent = rule_id

    model, result = assess(
        catalog,
        1,
        {"1": 1},
    )

    deepest = model.occurrences_by_rule[parent][0]
    assert result.facts[deepest].selected == 1
