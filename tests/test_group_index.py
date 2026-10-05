from internal.catalog import os_word_match
from internal.group_index import (
    GroupMembershipIndex,
    GroupSelectorIndex,
)


def test_group_selector_index_matches_oracle():
    selectors = {
        "auth",
        "^syslog",
        "missing|audit",
        "AUTHENTICATION",
        "^",
    }
    values = [
        "syslog,authentication_failed,",
        "audit,",
        "other,",
        "",
    ]
    index = GroupSelectorIndex(selectors)

    for value in values:
        expected = {
            selector
            for selector in selectors
            if os_word_match(selector, value)
        }
        assert index.match(value) == expected


def test_group_membership_updates_overwrite_without_occurrence_work():
    index = GroupMembershipIndex(
        ["old_group", "new_group", "^base"]
    )

    index.update("100001", "base,old_group,")

    assert index.matching_rules("old_group") == ("100001",)
    assert index.matching_rules("^base") == ("100001",)
    assert index.matching_rules("new_group") == ()

    index.update("100001", "custom,new_group,")

    assert index.matching_rules("old_group") == ()
    assert index.matching_rules("^base") == ()
    assert index.matching_rules("new_group") == ("100001",)


def test_group_selector_index_returns_selector_once_for_multiple_matches():
    selector = "auth|authentication"
    index = GroupSelectorIndex([selector])

    assert index.match("authentication,") == {selector}



def test_group_membership_preserves_rule_registration_order():
    index = GroupMembershipIndex(["shared"])

    index.update("100003", "shared,")
    index.update("100001", "shared,")
    index.update("100002", "shared,")

    assert index.matching_rules("shared") == (
        "100003",
        "100001",
        "100002",
    )


def test_group_membership_update_keeps_unaffected_member_order():
    index = GroupMembershipIndex(["shared", "other"])

    index.update("100001", "shared,")
    index.update("100002", "shared,")
    index.update("100003", "shared,")
    index.update("100002", "other,")

    assert index.matching_rules("shared") == ("100001", "100003")

    index.update("100002", "shared,")
    assert index.matching_rules("shared") == (
        "100001",
        "100003",
        "100002",
    )
