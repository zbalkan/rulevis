"""Indexed lookup of source RuleInfo groups for temporal OSMatch selectors.

Structural if_group uses OS_WordMatch and cannot reuse these memberships.
Candidate discovery uses the shared Aho-Corasick/prefix matcher as a superset;
os_match applies exact Wazuh temporal group semantics to each candidate.
"""
from __future__ import annotations

from collections.abc import Iterable

from internal.catalog import os_match
from internal.group_index import GroupSelectorIndex


class HistoricalGroupMembershipIndex:
    """Dynamic source membership for a fixed set of temporal selectors.

    Most positive patterns are indexed by their literal alternatives, with
    end anchors stripped only for conservative candidate discovery. Negated
    patterns and empty alternatives require unconditional candidate checks.
    RuleInfo group overwrites update membership without replaying history.
    """

    def __init__(self, selectors: Iterable[str]) -> None:
        self._selectors = {selector for selector in selectors if selector}
        self._always: set[str] = set()
        self._patterns: dict[str, set[str]] = {}
        self._members: dict[str, dict[str, None]] = {}
        self._selectors_by_rule: dict[str, set[str]] = {}

        for selector in self._selectors:
            if selector.startswith("!"):
                self._always.add(selector)
                continue
            terms = selector.split("|")
            if any(not term for term in terms):
                self._always.add(selector)
                continue
            alternatives = []
            for term in terms:
                # OSMatch suffix/exact anchors narrow the final match.
                # Removing '$' can only add false-positive candidates.
                candidate = term[:-1] if term.endswith("$") else term
                alternatives.append(candidate)
            marker = "|".join(alternatives)
            if not marker:
                self._always.add(selector)
            else:
                self._patterns.setdefault(marker, set()).add(selector)
        self._matcher = GroupSelectorIndex(self._patterns)

    def update(self, rule_id: str, runtime_group: str) -> None:
        candidate_selectors = set(self._always)
        for marker in self._matcher.match(runtime_group):
            candidate_selectors.update(self._patterns[marker])
        new = {
            selector for selector in candidate_selectors
            if os_match(selector, runtime_group)
        }
        old = self._selectors_by_rule.get(rule_id, set())
        for selector in old - new:
            members = self._members.get(selector)
            if members is not None:
                members.pop(rule_id, None)
                if not members:
                    del self._members[selector]
        for selector in new - old:
            self._members.setdefault(selector, {})[rule_id] = None
        self._selectors_by_rule[rule_id] = new

    def discard(self, rule_id: str) -> None:
        for selector in self._selectors_by_rule.pop(rule_id, set()):
            members = self._members.get(selector)
            if members is not None:
                members.pop(rule_id, None)
                if not members:
                    del self._members[selector]

    def matching_rules(self, selector: str) -> tuple[str, ...]:
        return tuple(self._members.get(selector, ()))
