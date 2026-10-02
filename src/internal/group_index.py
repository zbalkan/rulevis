from __future__ import annotations

from collections import deque
from collections.abc import Iterable


def _ascii_fold(data: bytes) -> bytes:
    return bytes(
        byte + 32 if 65 <= byte <= 90 else byte
        for byte in data
    )


class GroupSelectorIndex:
    """Index Wazuh OS_WordMatch-style if_group selectors.

    Unanchored alternatives are indexed with Aho-Corasick substring matching.
    Alternatives beginning with a caret are indexed in a prefix trie.  Query
    cost is linear in the runtime group string plus the number of reported
    selector matches.
    """

    def __init__(self, selectors: Iterable[str]) -> None:
        self._ac_next: list[dict[int, int]] = [{}]
        self._ac_fail: list[int] = [0]
        self._ac_output: list[set[str]] = [set()]

        self._prefix_next: list[dict[int, int]] = [{}]
        self._prefix_output: list[set[str]] = [set()]

        seen = {selector for selector in selectors if selector}
        for selector in seen:
            for alternative in selector.encode("utf-8").split(b"|"):
                if not alternative:
                    continue

                if alternative.startswith(b"^"):
                    self._add_prefix(
                        _ascii_fold(alternative[1:]),
                        selector,
                    )
                else:
                    self._add_substring(
                        _ascii_fold(alternative),
                        selector,
                    )

        self._build_failures()

    def _add_substring(self, pattern: bytes, selector: str) -> None:
        state = 0
        for byte in pattern:
            next_state = self._ac_next[state].get(byte)
            if next_state is None:
                next_state = len(self._ac_next)
                self._ac_next[state][byte] = next_state
                self._ac_next.append({})
                self._ac_fail.append(0)
                self._ac_output.append(set())
            state = next_state
        self._ac_output[state].add(selector)

    def _add_prefix(self, pattern: bytes, selector: str) -> None:
        state = 0
        if not pattern:
            self._prefix_output[state].add(selector)
            return

        for byte in pattern:
            next_state = self._prefix_next[state].get(byte)
            if next_state is None:
                next_state = len(self._prefix_next)
                self._prefix_next[state][byte] = next_state
                self._prefix_next.append({})
                self._prefix_output.append(set())
            state = next_state
        self._prefix_output[state].add(selector)

    def _build_failures(self) -> None:
        queue: deque[int] = deque()

        for state in self._ac_next[0].values():
            queue.append(state)
            self._ac_fail[state] = 0

        while queue:
            state = queue.popleft()

            for byte, child in self._ac_next[state].items():
                queue.append(child)
                fallback = self._ac_fail[state]

                while (
                    fallback
                    and byte not in self._ac_next[fallback]
                ):
                    fallback = self._ac_fail[fallback]

                self._ac_fail[child] = self._ac_next[fallback].get(
                    byte,
                    0,
                )
                self._ac_output[child].update(
                    self._ac_output[self._ac_fail[child]]
                )

    def match(self, runtime_group: str) -> set[str]:
        data = _ascii_fold(runtime_group.encode("utf-8"))
        matches = set(self._prefix_output[0])

        prefix_state = 0
        for byte in data:
            next_state = self._prefix_next[prefix_state].get(byte)
            if next_state is None:
                break
            prefix_state = next_state
            matches.update(self._prefix_output[prefix_state])

        state = 0
        for byte in data:
            while state and byte not in self._ac_next[state]:
                state = self._ac_fail[state]

            state = self._ac_next[state].get(byte, 0)
            matches.update(self._ac_output[state])

        return matches


class GroupMembershipIndex:
    """Dynamic logical-rule membership for compiled group selectors."""

    def __init__(self, selectors: Iterable[str]) -> None:
        self._matcher = GroupSelectorIndex(selectors)
        self._members: dict[str, set[str]] = {}
        self._selectors_by_rule: dict[str, set[str]] = {}

    def update(self, rule_id: str, runtime_group: str) -> None:
        old = self._selectors_by_rule.get(rule_id, set())
        new = self._matcher.match(runtime_group)

        for selector in old - new:
            members = self._members.get(selector)
            if members is not None:
                members.discard(rule_id)
                if not members:
                    del self._members[selector]

        for selector in new - old:
            self._members.setdefault(selector, set()).add(rule_id)

        self._selectors_by_rule[rule_id] = new

    def discard(self, rule_id: str) -> None:
        old = self._selectors_by_rule.pop(rule_id, set())
        for selector in old:
            members = self._members.get(selector)
            if members is not None:
                members.discard(rule_id)
                if not members:
                    del self._members[selector]

    def matching_rules(self, selector: str) -> frozenset[str]:
        return frozenset(self._members.get(selector, ()))
