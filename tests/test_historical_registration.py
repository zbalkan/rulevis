"""Registration-time tests against Wazuh 4.14.10 loader semantics.

These fixtures exercise the modeled loader, not a compiled analysisd binary.
"""

from internal.catalog import RuleCatalog
from internal.historical_registration import build_historical_registrations


def add_rule(
    catalog, rule_id, *, group="test,", if_sid=None,
    matched_sid=None, matched_group=None, overwrite=False,
):
    catalog.append(
        rule_id=str(rule_id), file="history.xml", source_level=5, accuracy=1,
        noalert=False, overwrite=overwrite, runtime_group=group,
        display_groups=[], category="syslog", if_sid=if_sid,
        if_level=None, if_group=None, if_matched_sid=matched_sid,
        if_matched_group=matched_group, conditions=[], temporal_conditions=[],
    )


def registrations(projection, source, relation):
    return tuple(
        entry for entry in projection.registrations
        if entry.source_rule_id == str(source) and entry.relation_type == relation
    )


def test_sid_registration_captures_existing_source_only():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="auth,")
    add_rule(catalog, 100020, if_sid="1", matched_sid=100010)
    add_rule(catalog, 100011, if_sid="1", group="auth,")

    projection = build_historical_registrations(catalog)
    sid = registrations(projection, 100010, "if_matched_sid")
    assert len(sid) == 1
    assert sid[0].consumer_rule_id == "100020"
    assert sid[0].consumer_declaration_sequence == 2
    assert not registrations(projection, 100011, "if_matched_sid")


def test_group_registration_excludes_sources_loaded_after_consumer():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="audit")
    add_rule(catalog, 100011, if_sid="1", group="audit,")
    projection = build_historical_registrations(catalog)

    assert projection.subscribers("100010", "if_matched_group") == ("100020",)
    assert projection.subscribers("100011", "if_matched_group") == ()


def test_rejected_consumer_does_not_register_any_source():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="999999", matched_group="audit")
    projection = build_historical_registrations(catalog)

    assert "100020" not in projection.structural_model.rules
    assert projection.registrations == ()


def test_sid_selector_shadows_group_selector():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_sid=100010, matched_group="audit")
    projection = build_historical_registrations(catalog)

    assert projection.subscribers("100010", "if_matched_sid") == ("100020",)
    assert projection.subscribers("100010", "if_matched_group") == ()


def test_both_active_history_lists_are_detected_without_claiming_alert_loss():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_sid=100010)
    add_rule(catalog, 100030, if_sid="1", matched_group="audit")
    projection = build_historical_registrations(catalog)

    assert projection.dual_history_sources() == ("100010",)
    assert projection.subscribers("100010", "if_matched_sid") == ("100020",)
    assert projection.subscribers("100010", "if_matched_group") == ("100030",)


def test_multiple_occurrences_preserve_physical_mark_multiplicity():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 2, group="root,")
    add_rule(catalog, 100010, if_sid="1,2", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="audit")
    projection = build_historical_registrations(catalog)

    records = registrations(projection, 100010, "if_matched_group")
    assert len(records) == 2
    assert len({record.source_occurrence_id for record in records}) == 2
    assert projection.subscribers("100010", "if_matched_group") == ("100020",)


def test_overwrites_do_not_replay_historical_registration():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="audit")
    add_rule(catalog, 100010, overwrite=True, group="renamed,")
    add_rule(catalog, 100030, if_sid="1", matched_group="audit")
    add_rule(catalog, 100020, overwrite=True, matched_sid=100010, group="another,")
    projection = build_historical_registrations(catalog)

    # The earlier consumer's list remains attached despite a later group edit.
    assert projection.subscribers("100010", "if_matched_group") == ("100020",)
    assert projection.subscribers("100010", "if_matched_sid") == ()
    assert not any(entry.consumer_rule_id == "100030" for entry in projection.registrations)
    initial = registrations(projection, 100010, "if_matched_group")[0]
    assert initial.source_group_at_registration == "audit,"


def test_group_match_uses_osmatch_instead_of_structural_wordmatch():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="^audit,$")
    projection = build_historical_registrations(catalog)
    assert projection.subscribers("100010", "if_matched_group") == ("100020",)


def test_registration_projection_does_not_change_normal_evaluation():
    from internal.evaluation import EvaluationBuilder

    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="audit")

    plain = EvaluationBuilder(catalog).build()
    projection = build_historical_registrations(catalog)
    assert plain.occurrences == projection.structural_model.occurrences
    assert plain.children == projection.structural_model.children
    assert plain.issues == projection.structural_model.issues


def test_sid_source_loaded_after_consumer_is_not_marked_retroactively():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100020, if_sid="1", matched_sid=100010)
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    projection = build_historical_registrations(catalog)
    assert projection.subscribers("100010", "if_matched_sid") == ()


def test_multiple_group_consumers_share_one_logical_source():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(catalog, 100020, if_sid="1", matched_group="audit")
    add_rule(catalog, 100030, if_sid="1", matched_group="audit")
    projection = build_historical_registrations(catalog)
    assert projection.subscribers("100010", "if_matched_group") == (
        "100020", "100030",
    )
    assert len(registrations(projection, 100010, "if_matched_group")) == 2


def test_builder_cannot_run_twice_even_without_registrations():
    import pytest
    from internal.historical_registration import HistoricalRegistrationBuilder

    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    builder = HistoricalRegistrationBuilder(catalog)
    assert builder.build().registrations == ()
    with pytest.raises(RuntimeError, match="only build once"):
        builder.build()


def test_overwrite_with_missing_base_is_inserted_and_registered():
    catalog = RuleCatalog()
    add_rule(catalog, 1, group="root,")
    add_rule(catalog, 100010, if_sid="1", group="audit,")
    add_rule(
        catalog, 100020, if_sid="1", matched_group="audit",
        overwrite=True,
    )
    projection = build_historical_registrations(catalog)
    assert "100020" in projection.structural_model.rules
    assert projection.subscribers("100010", "if_matched_group") == ("100020",)
    assert any(
        issue.code == "OVERWRITE_RULE_NOT_FOUND"
        for issue in projection.structural_model.issues
    )
