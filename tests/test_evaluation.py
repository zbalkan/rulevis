from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder


def add_rule(
    catalog,
    rule_id,
    level,
    *,
    runtime_group="test,",
    category=None,
    accuracy=1,
    noalert=False,
    overwrite=False,
    if_sid=None,
    if_level=None,
    if_group=None,
    if_matched_sid=None,
    if_matched_group=None,
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
        if_matched_sid=if_matched_sid,
        if_matched_group=if_matched_group,
        conditions=[],
        temporal_conditions=[],
    )


def test_if_sid_builds_source_faithful_chain():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="windows")
    add_rule(catalog, 100001, 5, if_sid="1")
    add_rule(catalog, 100002, 7, if_sid="100001")

    model = EvaluationBuilder(catalog).build()

    root = model.occurrences_by_rule["1"][0]
    child = model.occurrences_by_rule["100001"][0]
    leaf = model.occurrences_by_rule["100002"][0]

    assert model.children[None] == (root,)
    assert model.children[root] == (child,)
    assert model.children[child] == (leaf,)
    assert model.rules["100002"].category == "windows"


def test_if_group_uses_os_word_match_index():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, runtime_group="root,", category="test")
    add_rule(
        catalog,
        100010,
        5,
        runtime_group="syslog,authentication_failed,",
        if_sid="1",
    )
    add_rule(
        catalog,
        100011,
        7,
        if_group="AUTHENTICATION",
    )

    model = EvaluationBuilder(catalog).build()

    parent = model.occurrences_by_rule["100010"][0]
    child = model.occurrences_by_rule["100011"][0]

    assert model.children[parent] == (child,)


def test_if_level_attaches_to_every_qualifying_occurrence():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 10, category="a")
    add_rule(catalog, 2, 8, category="b")
    add_rule(catalog, 100020, 7, if_level=8)

    model = EvaluationBuilder(catalog).build()

    occurrences = model.occurrences_by_rule["100020"]
    assert len(occurrences) == 2

    parents = {
        model.occurrences[occurrence].parent_id
        for occurrence in occurrences
    }
    assert parents == {
        model.occurrences_by_rule["1"][0],
        model.occurrences_by_rule["2"][0],
    }


def test_overwrite_changes_priority_without_repositioning():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100030, 10, if_sid="1")
    add_rule(catalog, 100031, 5, if_sid="1")
    add_rule(catalog, 100030, 1, overwrite=True)
    add_rule(catalog, 100032, 7, if_sid="1")

    model = EvaluationBuilder(catalog).build()

    root = model.occurrences_by_rule["1"][0]
    ordered_rules = [
        model.occurrences[occurrence].rule_id
        for occurrence in model.children[root]
    ]

    assert ordered_rules == ["100032", "100030", "100031"]


def test_temporal_sid_is_synthesized_as_structural_parent():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100040, 5, if_sid="1")
    add_rule(catalog, 100041, 8, if_matched_sid=100040)

    model = EvaluationBuilder(catalog).build()

    parent = model.occurrences_by_rule["100040"][0]
    child = model.occurrences_by_rule["100041"][0]
    assert model.children[parent] == (child,)


def test_default_category_uses_first_matching_preorder_occurrence():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="windows")
    add_rule(catalog, 2, 0, category="syslog")
    add_rule(catalog, 100050, 5, category="windows")
    add_rule(catalog, 100051, 6, category="windows")

    model = EvaluationBuilder(catalog).build()

    root = model.occurrences_by_rule["1"][0]
    ordered = [
        model.occurrences[occurrence].rule_id
        for occurrence in model.children[root]
    ]
    assert ordered == ["100051", "100050"]


def test_missing_default_category_parent_is_rejected():
    catalog = RuleCatalog()
    add_rule(catalog, 100060, 5, category="windows")

    model = EvaluationBuilder(catalog).build()

    assert "100060" not in model.rules
    assert [(issue.code, issue.rule_id) for issue in model.issues] == [
        ("CATEGORY_NOT_FOUND", "100060")
    ]


def test_overwrite_category_updates_preorder_index():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="windows")
    add_rule(catalog, 2, 0, category="syslog")
    add_rule(catalog, 100070, 5, if_sid="1")
    add_rule(
        catalog,
        100070,
        5,
        category="custom",
        overwrite=True,
    )
    add_rule(catalog, 100071, 6, category="custom")

    model = EvaluationBuilder(catalog).build()

    parent = model.occurrences_by_rule["100070"][0]
    child = model.occurrences_by_rule["100071"][0]
    assert model.children[parent] == (child,)



def test_omitted_category_attaches_to_syslog_root():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="syslog")
    add_rule(catalog, 100080, 5)

    model = EvaluationBuilder(catalog).build()

    root = model.occurrences_by_rule["1"][0]
    child = model.occurrences_by_rule["100080"][0]
    assert model.children[root] == (child,)
    assert model.rules["100080"].category == "syslog"


def test_invalid_rule_id_is_reported_without_crashing():
    catalog = RuleCatalog()
    add_rule(catalog, "not-a-number", 5)

    model = EvaluationBuilder(catalog).build()

    assert "not-a-number" not in model.rules
    assert [
        (issue.code, issue.rule_id, issue.selector)
        for issue in model.issues
    ] == [
        ("INVALID_RULE_ID", "not-a-number", "not-a-number")
    ]


def test_valid_rule_id_is_canonicalized_before_evaluation():
    catalog = RuleCatalog()
    add_rule(catalog, "000001", 0, category="syslog")
    add_rule(catalog, 100081, 5, if_sid="1")

    model = EvaluationBuilder(catalog).build()

    assert "1" in model.rules
    root = model.occurrences_by_rule["1"][0]
    child = model.occurrences_by_rule["100081"][0]
    assert model.children[root] == (child,)



def test_missing_overwrite_if_group_is_processed_as_new_rule():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(
        catalog,
        100090,
        5,
        runtime_group="source_group,",
        if_sid="1",
    )
    add_rule(
        catalog,
        100091,
        7,
        overwrite=True,
        if_group="source_group",
    )

    model = EvaluationBuilder(catalog).build()

    parent = model.occurrences_by_rule["100090"][0]
    child = model.occurrences_by_rule["100091"][0]
    assert model.children[parent] == (child,)
    assert (
        "OVERWRITE_RULE_NOT_FOUND",
        "100091",
    ) in {
        (issue.code, issue.rule_id)
        for issue in model.issues
    }


def test_missing_overwrite_if_matched_group_uses_synthesized_parent():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(
        catalog,
        100092,
        5,
        runtime_group="source_group,",
        if_sid="1",
    )
    add_rule(
        catalog,
        100093,
        7,
        overwrite=True,
        if_matched_group="source_group",
    )

    model = EvaluationBuilder(catalog).build()

    parent = model.occurrences_by_rule["100092"][0]
    child = model.occurrences_by_rule["100093"][0]
    assert model.children[parent] == (child,)
    assert (
        "OVERWRITE_RULE_NOT_FOUND",
        "100093",
    ) in {
        (issue.code, issue.rule_id)
        for issue in model.issues
    }



def test_if_sid_attaches_to_each_occurrence_reached_by_wazuh_preorder():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 5, category="first")
    add_rule(catalog, 2, 10, category="second")
    add_rule(catalog, 100100, 6, if_level=1)
    add_rule(catalog, 100101, 7, if_sid="100100")

    model = EvaluationBuilder(catalog).build()

    root_first = model.occurrences_by_rule["1"][0]
    root_second = model.occurrences_by_rule["2"][0]
    parents = {
        model.occurrences[occurrence_id].parent_id: occurrence_id
        for occurrence_id in model.occurrences_by_rule["100100"]
    }

    # Root 2 was loaded later but its higher priority places it first in
    # Wazuh's current tree. The SID search must therefore visit that
    # occurrence first and still continue into the other root subtree.
    expected_parents = [
        parents[root_second],
        parents[root_first],
    ]
    actual_parents = [
        model.occurrences[occurrence_id].parent_id
        for occurrence_id in model.occurrences_by_rule["100101"]
    ]

    assert actual_parents == expected_parents


def test_if_sid_stops_after_first_direct_match_in_one_sibling_list():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100110, 5, if_sid="1,1")
    add_rule(catalog, 100111, 7, if_sid="100110")

    model = EvaluationBuilder(catalog).build()

    repeated = model.occurrences_by_rule["100110"]
    assert len(repeated) == 2

    children = model.occurrences_by_rule["100111"]
    assert len(children) == 1
    assert model.occurrences[children[0]].parent_id == repeated[0]



def test_failed_temporal_sid_attachment_leaves_no_runtime_occurrences():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(
        catalog,
        100120,
        5,
        if_sid="1,999999",
        if_matched_sid=1,
    )
    add_rule(catalog, 100121, 6, if_sid="100120")

    builder = EvaluationBuilder(catalog)
    model = builder.build()

    root = model.occurrences_by_rule["1"][0]
    assert "100120" not in model.rules
    assert "100120" not in model.occurrences_by_rule
    assert "100121" not in model.rules
    assert set(model.graph.nodes) == {root}
    assert list(builder.order) == [
        builder.enter_token_by_occurrence[root],
        builder.exit_token_by_occurrence[root],
    ]
    assert (
        "SID_NOT_FOUND",
        "100120",
        "999999",
    ) in {
        (issue.code, issue.rule_id, issue.selector)
        for issue in model.issues
    }


def test_ordinary_multi_sid_keeps_valid_attachments_when_one_sid_is_missing():
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="test")
    add_rule(catalog, 100122, 5, if_sid="1,999999")

    model = EvaluationBuilder(catalog).build()

    root = model.occurrences_by_rule["1"][0]
    child = model.occurrences_by_rule["100122"][0]
    assert model.children[root] == (child,)
    assert (
        "SID_NOT_FOUND",
        "100122",
        "999999",
    ) in {
        (issue.code, issue.rule_id, issue.selector)
        for issue in model.issues
    }



def test_if_level_uses_encoded_load_priority_like_wazuh():
    catalog = RuleCatalog()
    # Wazuh maps level 0 / accuracy 1 to 9900 during RuleNode loading,
    # so it qualifies for if_level=5 even though its runtime level is 0.
    add_rule(catalog, 1, 0, accuracy=1, category="zero")
    # accuracy=0 leaves level 10 encoded as 10, below the 500 threshold.
    add_rule(catalog, 2, 10, accuracy=0, category="low-priority")
    add_rule(catalog, 3, 10, accuracy=1, category="normal")
    add_rule(catalog, 100130, 7, if_level=5)

    model = EvaluationBuilder(catalog).build()

    parents = {
        model.occurrences[occurrence_id].parent_id
        for occurrence_id in model.occurrences_by_rule["100130"]
    }
    assert parents == {
        model.occurrences_by_rule["1"][0],
        model.occurrences_by_rule["3"][0],
    }
    assert model.occurrences_by_rule["2"][0] not in parents
