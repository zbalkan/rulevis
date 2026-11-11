"""Regression tests for indexed load-time history registration.

The reference implementation deliberately performs the previous full preorder
scan, so comparisons test both output identity and registration ordering.
"""
from __future__ import annotations

import random

from internal.catalog import RuleCatalog, os_match
from internal.evaluation import EvaluationBuilder
from internal.historical_group_index import HistoricalGroupMembershipIndex
from internal.historical_registration import (
    HistoricalRegistrationBuilder,
    build_historical_registrations,
)


class FullScanReference(HistoricalRegistrationBuilder):
    def _candidate_occurrences(self, selector, search, builder):
        return [
            occurrence_id for occurrence_id in builder._occurrences_in_preorder()
            if (
                builder.occurrences[occurrence_id].rule_id == selector
                if search == "if_matched_sid"
                else os_match(
                    selector,
                    builder.rules[
                        builder.occurrences[occurrence_id].rule_id
                    ].runtime_group,
                )
            )
        ]


def _add(catalog, rule_id, **attrs):
    catalog.append(
        rule_id=str(rule_id), file="performance.xml",
        source_level=attrs.get("level", 5), accuracy=1,
        noalert=False, overwrite=attrs.get("overwrite", False),
        runtime_group=attrs.get("group", "test,"),
        display_groups=[], category="syslog",
        if_sid=attrs.get("if_sid"),
        if_level=None, if_group=None,
        if_matched_sid=attrs.get("matched_sid"),
        if_matched_group=attrs.get("matched_group"),
        conditions=[], temporal_conditions=[],
    )


def _catalog(seed):
    rng = random.Random(seed)
    catalog = RuleCatalog()
    _add(catalog, 1, group="root,")
    _add(catalog, 2, group="root,")
    groups = ["audit,", "authentication,", "root,", "audit,extra,", "Déjà,"]
    selectors = [
        "audit", "authentication", "^audit", "audit,$",
        "^audit,$", "missing", "!audit", "audit|missing",
        "!audit|root", "|", "^root,$", "Déjà", "$",
    ]
    for offset in range(32):
        rule_id = 100100 + offset
        attrs = {
            "group": rng.choice(groups),
            "if_sid": rng.choice(["1", "2", "1,2"]),
        }
        if offset % 3 == 0:
            attrs["matched_group"] = rng.choice(selectors)
        elif offset % 3 == 1:
            attrs["matched_sid"] = rng.choice([
                100100, rule_id - 1, 100131, 999999,
            ])
        _add(catalog, rule_id, **attrs)
        if offset % 7 == 0:
            _add(catalog, rule_id, group=rng.choice(groups), overwrite=True)
    return catalog


def test_indexed_builder_matches_full_scan_for_seeded_load_sequences():
    for seed in range(12):
        catalog = _catalog(seed)
        reference = FullScanReference(catalog).build()
        actual = build_historical_registrations(catalog)
        assert actual.registrations == reference.registrations
        assert actual.structural_model.occurrences == reference.structural_model.occurrences
        assert actual.structural_model.issues == reference.structural_model.issues


def test_indexed_builder_never_materializes_full_preorder(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Historical registration used full-tree scan")

    monkeypatch.setattr(EvaluationBuilder, "_occurrences_in_preorder", fail)
    catalog = _catalog(2)
    projection = build_historical_registrations(catalog)
    assert projection.registrations


def test_group_membership_index_matches_osmatch_with_overwrites_and_deletion():
    selectors = [
        "audit", "AUDIT", "^audit", "audit,$", "^audit,$",
        "missing", "!audit", "!audit|root", "audit|missing",
        "|", "^root,$", "Déjà", "$", "^$", "!", "foo||bar",
    ]
    groups = ["audit,", "audit,extra,", "root,", "other,", "Déjà,", "", "AUDIT,"]
    index = HistoricalGroupMembershipIndex(selectors)
    expected = {}
    for index_id, group in enumerate(groups):
        rule = str(index_id)
        index.update(rule, group)
        expected[rule] = group
    for selector in selectors:
        assert set(index.matching_rules(selector)) == {
            rule for rule, group in expected.items() if os_match(selector, group)
        }
    index.update("1", "nothing,")
    expected["1"] = "nothing,"
    index.discard("2")
    expected.pop("2")
    for selector in selectors:
        assert set(index.matching_rules(selector)) == {
            rule for rule, group in expected.items() if os_match(selector, group)
        }


def test_indexes_are_not_reused_between_independent_builds():
    catalog = _catalog(5)
    first = build_historical_registrations(catalog)
    second = build_historical_registrations(catalog)
    assert first.registrations == second.registrations
    assert first.dual_history_sources() == second.dual_history_sources()
