from __future__ import annotations

import heapq
import re
from itertools import islice
from dataclasses import dataclass, field
from typing import Callable, Optional

import networkx as nx

from internal.catalog import (
    RuleCatalog,
    RuleDeclaration,
    active_temporal_sid,
    normalize_rule_id,
    valid_if_sid,
    resolve_structural_parent_selectors,
)
from internal.group_index import GroupMembershipIndex
from internal.order import CategoryOrder, PrioritySequence


@dataclass
class RuleState:
    rule_id: str
    load_priority: int
    runtime_group: str
    category: Optional[str]
    noalert: bool
    conditions: tuple[dict[str, object], ...]
    temporal_conditions: tuple[dict[str, object], ...]
    parent_relation: Optional[str] = None
    parent_selector: Optional[str] = None
    parent_synthesized_from: Optional[str] = None


@dataclass(frozen=True)
class Occurrence:
    occurrence_id: int
    rule_id: str
    parent_id: Optional[int]
    matched_selector: Optional[str] = None


@dataclass(frozen=True)
class LoadIssue:
    code: str
    rule_id: str
    selector: Optional[str] = None


@dataclass
class EvaluationModel:
    graph: nx.DiGraph
    rules: dict[str, RuleState]
    occurrences: dict[int, Occurrence]
    children: dict[Optional[int], tuple[int, ...]]
    occurrences_by_rule: dict[str, tuple[int, ...]]
    issues: tuple[LoadIssue, ...]


class OccurrenceBudgetExceeded(RuntimeError):
    """The RuleVis-specific occurrence budget prevented another allocation."""

    def __init__(self, rule_id: str, limit: int, node_count: int) -> None:
        self.rule_id = rule_id
        self.limit = limit
        self.node_count = node_count
        super().__init__(
            f"Rule {rule_id} exceeds RuleVis occurrence budget "
            f"of {limit} (allocated: {node_count})"
        )


class EvaluationBuilder:
    """Replay the Wazuh 4.14.10 RuleNode construction semantics."""

    def __init__(
        self, catalog: RuleCatalog, *, max_occurrences: int = 100_000,
        on_accepted: Optional[Callable[[RuleDeclaration, "EvaluationBuilder"], None]] = None
    ) -> None:
        if (
            isinstance(max_occurrences, bool)
            or not isinstance(max_occurrences, int)
            or max_occurrences < 1
        ):
            raise ValueError("max_occurrences must be a positive integer")
        self.max_occurrences = max_occurrences
        self.on_accepted = on_accepted
        self.catalog = catalog
        self.graph = nx.DiGraph()
        self.rules: dict[str, RuleState] = {}
        self.occurrences: dict[int, Occurrence] = {}
        self.occurrences_by_rule: dict[str, list[int]] = {}
        self.sequences: dict[Optional[int], PrioritySequence] = {
            None: PrioritySequence()
        }
        self.parent_by_occurrence: dict[int, Optional[int]] = {}
        self.issues: list[LoadIssue] = []
        self._next_occurrence = 0
        self.order = CategoryOrder()
        self.enter_token_by_occurrence: dict[int, int] = {}
        self.exit_token_by_occurrence: dict[int, int] = {}
        self.occurrence_by_enter_token: dict[int, int] = {}
        self.category_bits: dict[Optional[str], int] = {}

        selectors = {
            parents.if_group
            for declaration in catalog.declarations
            for parents in [self._effective_parents(declaration)]
            if (
                parents.if_sid is None
                and parents.if_level is None
                and parents.if_group
            )
        }
        self.group_index = GroupMembershipIndex(selectors)

    @staticmethod
    def _effective_parents(
        declaration: RuleDeclaration,
    ):
        return resolve_structural_parent_selectors(
            if_sid=declaration.if_sid,
            if_level=declaration.if_level,
            if_group=declaration.if_group,
            if_matched_sid=declaration.if_matched_sid,
            if_matched_group=declaration.if_matched_group,
        )

    def _category_bit(self, category: Optional[str]) -> int:
        bit = self.category_bits.get(category)
        if bit is None:
            bit = 1 << len(self.category_bits)
            self.category_bits[category] = bit
        return bit

    def _set_category(
        self,
        state: RuleState,
        category: Optional[str],
    ) -> None:
        if state.category == category:
            return

        state.category = category
        bit = self._category_bit(category)
        for occurrence_id in self.occurrences_by_rule.get(
            state.rule_id,
            (),
        ):
            self.order.update_category(
                self.enter_token_by_occurrence[occurrence_id],
                bit,
            )

    def _register_state(self, state: RuleState) -> None:
        self.rules[state.rule_id] = state
        self.group_index.update(state.rule_id, state.runtime_group)

    def _unregister_state(self, state: RuleState) -> None:
        self.rules.pop(state.rule_id, None)
        self.group_index.discard(state.rule_id)

    def _occurrences_in_preorder(self) -> list[int]:
        """Snapshot runtime occurrences in current RuleNode preorder."""
        return [
            self.occurrence_by_enter_token[token]
            for token in self.order
            if token in self.occurrence_by_enter_token
        ]

    def _ensure_occurrence_budget(self, rule_id: str) -> None:
        if self._next_occurrence >= self.max_occurrences:
            raise OccurrenceBudgetExceeded(
                rule_id, self.max_occurrences, self._next_occurrence
            )

    def _new_occurrence(
        self,
        rule_id: str,
        parent_id: Optional[int],
        *,
        matched_selector: Optional[str] = None,
    ) -> int:
        self._ensure_occurrence_budget(rule_id)
        occurrence_id = self._next_occurrence
        self._next_occurrence += 1

        state = self.rules[rule_id]
        sequence = self.sequences.setdefault(
            parent_id,
            PrioritySequence(),
        )
        insertion_index = sequence.insert(
            occurrence_id,
            state.load_priority,
        )

        next_sibling = (
            sequence.item_at(insertion_index + 1)
            if insertion_index + 1 < len(sequence)
            else None
        )

        enter_token = occurrence_id * 2
        exit_token = enter_token + 1
        category_bit = self._category_bit(state.category)

        if next_sibling is not None:
            reference = self.enter_token_by_occurrence[next_sibling]
            self.order.insert_before(
                reference,
                enter_token,
                category_bit,
            )
            self.order.insert_before(reference, exit_token)
        elif parent_id is not None:
            reference = self.exit_token_by_occurrence[parent_id]
            self.order.insert_before(
                reference,
                enter_token,
                category_bit,
            )
            self.order.insert_before(reference, exit_token)
        else:
            self.order.append(enter_token, category_bit)
            self.order.append(exit_token)

        self.enter_token_by_occurrence[occurrence_id] = enter_token
        self.exit_token_by_occurrence[occurrence_id] = exit_token
        self.occurrence_by_enter_token[enter_token] = occurrence_id

        occurrence = Occurrence(
            occurrence_id=occurrence_id,
            rule_id=rule_id,
            parent_id=parent_id,
            matched_selector=matched_selector,
        )
        self.occurrences[occurrence_id] = occurrence
        self.parent_by_occurrence[occurrence_id] = parent_id
        self.occurrences_by_rule.setdefault(rule_id, []).append(
            occurrence_id
        )
        self.sequences.setdefault(
            occurrence_id,
            PrioritySequence(),
        )

        self.graph.add_node(occurrence_id, rule_id=rule_id)
        if parent_id is not None:
            self.graph.add_edge(parent_id, occurrence_id)

        return occurrence_id

    def _update_overwrite(
        self,
        state: RuleState,
        declaration: RuleDeclaration,
    ) -> None:
        old_priority = state.load_priority
        state.load_priority = declaration.load_priority
        state.runtime_group = declaration.runtime_group
        self._set_category(state, declaration.category)
        state.noalert = declaration.noalert
        state.conditions = declaration.conditions
        state.temporal_conditions = declaration.temporal_conditions

        self.group_index.update(state.rule_id, state.runtime_group)

        if old_priority != state.load_priority:
            for occurrence_id in self.occurrences_by_rule.get(
                state.rule_id,
                (),
            ):
                parent_id = self.parent_by_occurrence[occurrence_id]
                self.sequences[parent_id].update_priority(
                    occurrence_id,
                    state.load_priority,
                )

    @staticmethod
    def _sid_values(value: str) -> list[tuple[str, str]]:
        """Preserve each raw SID token alongside its canonical lookup ID."""
        values: list[tuple[str, str]] = []
        for sid in re.split(r"[,\s]+", value.strip()):
            if not sid:
                continue
            normalized = normalize_rule_id(sid)
            values.append((sid, normalized if normalized is not None else sid))
        return values

    def _sid_parent_occurrences(self, rule_id: str) -> list[int]:
        """Return SID matches in Wazuh's current recursive tree order."""
        candidates = self.occurrences_by_rule.get(rule_id, ())
        ranked = sorted(
            (
                self.order.rank(
                    self.enter_token_by_occurrence[occurrence_id]
                ),
                occurrence_id,
            )
            for occurrence_id in candidates
        )

        matches: list[int] = []
        suppressed_until = -1

        for enter_rank, occurrence_id in ranked:
            if enter_rank < suppressed_until:
                continue

            matches.append(occurrence_id)
            parent_id = self.parent_by_occurrence[occurrence_id]
            if parent_id is None:
                suppressed_until = len(self.order)
            else:
                suppressed_until = self.order.rank(
                    self.exit_token_by_occurrence[parent_id]
                )

        return matches

    def _attach_if_sid(
        self,
        state: RuleState,
        declaration: RuleDeclaration,
        selector: str,
    ) -> bool:
        planned: list[tuple[str, list[int]]] = []

        # Resolve every required parent before mutating the occurrence tree.
        # if_matched_sid failures reject the rule, so staging prevents
        # partially created RuleNodes from surviving that rejection.
        for raw_sid, sid in self._sid_values(selector):
            parent_ids = self._sid_parent_occurrences(sid)
            if not parent_ids:
                self.issues.append(
                    LoadIssue("SID_NOT_FOUND", state.rule_id, sid)
                )
                if active_temporal_sid(declaration.if_matched_sid):
                    return False
                continue

            planned.append((raw_sid, parent_ids))

        attached = False
        for raw_sid, parent_ids in planned:
            for parent_id in parent_ids:
                parent_rule_id = self.occurrences[parent_id].rule_id
                self._set_category(
                    state,
                    self.rules[parent_rule_id].category,
                )
                self._new_occurrence(
                    state.rule_id, parent_id, matched_selector=raw_sid
                )
                attached = True

        return attached

    def _attach_if_level(
        self,
        state: RuleState,
        level: int,
    ) -> bool:
        if level == 0:
            self.issues.append(
                LoadIssue("INVALID_IF_LEVEL", state.rule_id, "0")
            )
            return False

        threshold = level * 100
        # A bounded snapshot prevents the full preorder list from being
        # materialized before the allocation budget can reject a rule.
        candidate_limit = self.max_occurrences - self._next_occurrence + 1
        candidates = (
            self.occurrence_by_enter_token[token]
            for token in self.order
            if token in self.occurrence_by_enter_token
        )
        eligible = (
            occurrence_id
            for occurrence_id in candidates
            if (
                self.occurrences[occurrence_id].rule_id != state.rule_id
                and self.rules[
                    self.occurrences[occurrence_id].rule_id
                ].load_priority >= threshold
            )
        )
        parent_ids = list(islice(eligible, candidate_limit))

        attached = False
        for parent_id in parent_ids:
            self._new_occurrence(state.rule_id, parent_id)
            attached = True

        if not attached:
            self.issues.append(
                LoadIssue(
                    "LEVEL_NOT_FOUND",
                    state.rule_id,
                    str(level),
                )
            )

        return attached

    def _attach_if_group(
        self,
        state: RuleState,
        selector: str,
    ) -> bool:
        parent_rules = (
            rule_id
            for rule_id in self.group_index.matching_rules(selector)
            if rule_id != state.rule_id
        )
        # Snapshot at most the remaining budget plus one parent. This
        # preserves the existing partial-insertion behavior at the boundary
        # without materializing and sorting every group candidate.
        candidate_limit = self.max_occurrences - self._next_occurrence + 1
        parent_ids = heapq.nsmallest(
            candidate_limit,
            (
                occurrence_id
                for rule_id in parent_rules
                for occurrence_id in self.occurrences_by_rule.get(
                    rule_id,
                    (),
                )
            ),
            key=lambda occurrence_id: self.order.rank(
                self.enter_token_by_occurrence[occurrence_id]
            ),
        )

        attached = False
        for parent_id in parent_ids:
            self._new_occurrence(state.rule_id, parent_id)
            attached = True

        if not attached:
            self.issues.append(
                LoadIssue("GROUP_NOT_FOUND", state.rule_id, selector)
            )

        return attached

    def _notify_accepted(self, declaration: RuleDeclaration) -> None:
        """Expose the current tree immediately after a new accepted rule.

        Called only for newly inserted RuleInfo objects. Wazuh does not rerun
        OS_MarkID/OS_MarkGroup when an existing RuleInfo is overwritten.
        """
        if self.on_accepted is not None:
            self.on_accepted(declaration, self)

    def _process(self, declaration: RuleDeclaration) -> None:
        normalized_rule_id = normalize_rule_id(declaration.rule_id)
        if normalized_rule_id is None:
            self.issues.append(
                LoadIssue(
                    "INVALID_RULE_ID",
                    declaration.rule_id,
                    declaration.rule_id,
                )
            )
            return

        if not valid_if_sid(declaration.if_sid):
            self.issues.append(
                LoadIssue("INVALID_IF_SID", declaration.rule_id, declaration.if_sid)
            )
            return

        if declaration.invalid_if_level is not None:
            self.issues.append(
                LoadIssue(
                    "INVALID_IF_LEVEL",
                    declaration.rule_id,
                    declaration.invalid_if_level,
                )
            )
            return

        if declaration.invalid_if_matched_sid is not None:
            self.issues.append(
                LoadIssue(
                    "INVALID_IF_MATCHED_SID",
                    declaration.rule_id,
                    declaration.invalid_if_matched_sid,
                )
            )
            return

        existing = self.rules.get(declaration.rule_id)

        if existing is not None and not declaration.overwrite:
            self.issues.append(
                LoadIssue("DUPLICATE_RULE_ID", declaration.rule_id)
            )
            return

        if existing is not None and declaration.overwrite:
            self._update_overwrite(existing, declaration)
            return

        overwrite_missing = declaration.overwrite and existing is None
        if overwrite_missing:
            self.issues.append(
                LoadIssue("OVERWRITE_RULE_NOT_FOUND", declaration.rule_id)
            )

        parents = self._effective_parents(declaration)
        parent_synthesized_from = None
        if int(normalized_rule_id) < 10:
            parent_relation, parent_selector = "root", None
        elif parents.if_sid:
            parent_relation = "if_sid"
            parent_selector = parents.if_sid
            if not declaration.if_sid:
                parent_synthesized_from = "if_matched_sid"
        elif parents.if_level is not None:
            parent_relation, parent_selector = (
                "if_level", str(parents.if_level)
            )
        elif parents.if_group:
            parent_relation = "if_group"
            parent_selector = parents.if_group
            if not declaration.if_group:
                parent_synthesized_from = "if_matched_group"
        else:
            parent_relation, parent_selector = "category", declaration.category

        state = RuleState(
            rule_id=declaration.rule_id,
            load_priority=declaration.load_priority,
            runtime_group=declaration.runtime_group,
            category=declaration.category,
            noalert=declaration.noalert,
            conditions=declaration.conditions,
            temporal_conditions=declaration.temporal_conditions,
            parent_relation=parent_relation,
            parent_selector=parent_selector,
            parent_synthesized_from=parent_synthesized_from,
        )
        self._register_state(state)

        if int(normalized_rule_id) < 10:
            self._new_occurrence(state.rule_id, None)
            self._notify_accepted(declaration)
            return

        if parents.if_sid:
            attached = self._attach_if_sid(
                state,
                declaration,
                parents.if_sid,
            )
        elif parents.if_level is not None:
            attached = self._attach_if_level(
                state,
                parents.if_level,
            )
        elif parents.if_group:
            attached = self._attach_if_group(
                state,
                parents.if_group,
            )
        else:
            # Wazuh category fallback inspects top-level siblings only.
            # It never descends into children for this selector.
            parent_id = next(
                (
                    occurrence_id
                    for occurrence_id in self.sequences[None]
                    if self.rules[
                        self.occurrences[occurrence_id].rule_id
                    ].category == state.category
                ),
                None,
            )
            if parent_id is None:
                self.issues.append(
                    LoadIssue(
                        "CATEGORY_NOT_FOUND",
                        state.rule_id,
                        state.category,
                    )
                )
                attached = False
            else:
                parent_rule_id = self.occurrences[parent_id].rule_id
                self._set_category(
                    state,
                    self.rules[parent_rule_id].category,
                )
                self._new_occurrence(state.rule_id, parent_id)
                attached = True

        if not attached:
            self._unregister_state(state)
        else:
            self._notify_accepted(declaration)

    def build(self) -> EvaluationModel:
        for declaration in self.catalog.declarations:
            self._process(declaration)

        children = {
            parent_id: tuple(sequence)
            for parent_id, sequence in self.sequences.items()
            if len(sequence)
        }
        occurrence_map = {
            rule_id: tuple(occurrences)
            for rule_id, occurrences in self.occurrences_by_rule.items()
        }

        if not nx.is_directed_acyclic_graph(self.graph):
            raise AssertionError("Runtime occurrence graph must be acyclic")

        return EvaluationModel(
            graph=self.graph,
            rules=dict(self.rules),
            occurrences=dict(self.occurrences),
            children=children,
            occurrences_by_rule=occurrence_map,
            issues=tuple(self.issues),
        )


def project_occurrence_relationships(
    model: EvaluationModel,
) -> nx.MultiDiGraph:
    """Collapse accepted RuleNode occurrences into logical runtime edges.

    The projection preserves attachment multiplicity. It is not the declared
    dependency graph and does not imply historical-event correlation.
    """
    projected = nx.MultiDiGraph()
    for rule_id in model.rules:
        projected.add_node(
            rule_id,
            occurrence_count=len(model.occurrences_by_rule.get(rule_id, ())),
        )

    for occurrence in model.occurrences.values():
        if occurrence.parent_id is None:
            continue
        parent_rule = model.occurrences[occurrence.parent_id].rule_id
        child_rule = occurrence.rule_id
        state = model.rules[child_rule]
        relation = state.parent_relation or "unknown"
        # A multi-SID declaration can attach under different parents.
        # Preserve the exact source token for each physical attachment so
        # comparisons can match GraphGenerator's per-SID declared edges.
        selector = (
            occurrence.matched_selector
            if relation == "if_sid" and occurrence.matched_selector is not None
            else state.parent_selector
        )
        synthesized_from = state.parent_synthesized_from
        key = (relation, selector, synthesized_from)
        if projected.has_edge(parent_rule, child_rule, key):
            projected.edges[parent_rule, child_rule, key][
                "occurrence_count"
            ] += 1
        else:
            projected.add_edge(
                parent_rule,
                child_rule,
                key=key,
                relation_type=relation,
                selector=selector,
                synthesized_from=synthesized_from,
                occurrence_count=1,
            )

    return projected
