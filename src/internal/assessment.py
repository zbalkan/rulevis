from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import networkx as nx

from internal.catalog import wazuh_runtime_level
from internal.domains import BitsetDomain
from internal.evaluation import EvaluationModel


@dataclass(frozen=True)
class OccurrenceFacts:
    candidate: int
    reached: int
    matched: int
    terminal: int
    selected: int
    dropped: int
    shadowed: int


@dataclass(frozen=True)
class AssessmentResult:
    facts: dict[int, OccurrenceFacts]
    termination: dict[int, int]
    selected_by_rule: dict[str, int]
    dropped_by_rule: dict[str, int]


class BitsetAssessor:
    """Exact bulk evaluator over a finite synthetic event universe."""

    def __init__(
        self,
        model: EvaluationModel,
        domain: BitsetDomain,
        predicates: dict[str, int],
    ) -> None:
        self.model = model
        self.domain = domain
        self.predicates = {
            rule_id: domain.normalize(predicate)
            for rule_id, predicate in predicates.items()
        }

    def _predicate(self, rule_id: str) -> int:
        return self.predicates.get(rule_id, self.domain.top())

    def assess(self) -> AssessmentResult:
        topological = list(nx.topological_sort(self.model.graph))
        termination: dict[int, int] = {}
        child_termination: dict[int, int] = {}

        # Bottom-up: summarize the event region for which each subtree
        # returns a rule.  Ordinary and level-zero rules terminate for every
        # local match; NO_ALERT rules terminate only through descendants.
        for occurrence_id in reversed(topological):
            occurrence = self.model.occurrences[occurrence_id]
            state = self.model.rules[occurrence.rule_id]
            predicate = self._predicate(occurrence.rule_id)

            descendants = self.domain.bottom()
            for child_id in self.model.children.get(
                occurrence_id,
                (),
            ):
                descendants = self.domain.union(
                    descendants,
                    termination[child_id],
                )

            child_termination[occurrence_id] = descendants
            if state.noalert:
                termination[occurrence_id] = self.domain.intersect(
                    predicate,
                    descendants,
                )
            else:
                termination[occurrence_id] = predicate

        facts: dict[int, OccurrenceFacts] = {}
        selected_by_rule: dict[str, int] = {}
        dropped_by_rule: dict[str, int] = {}

        # Top-down: each sibling list receives one actual residual region and
        # one candidate region that deliberately ignores prior siblings.
        queue = deque([
            (
                None,
                self.domain.top(),
                self.domain.top(),
            )
        ])

        while queue:
            parent_id, actual_input, candidate_input = queue.popleft()
            residual = actual_input

            for occurrence_id in self.model.children.get(parent_id, ()):
                occurrence = self.model.occurrences[occurrence_id]
                state = self.model.rules[occurrence.rule_id]
                predicate = self._predicate(occurrence.rule_id)

                candidate = self.domain.intersect(
                    candidate_input,
                    predicate,
                )
                reached = residual
                matched = self.domain.intersect(
                    reached,
                    predicate,
                )
                descendant_terminal = self.domain.intersect(
                    matched,
                    child_termination[occurrence_id],
                )
                self_region = self.domain.difference(
                    matched,
                    descendant_terminal,
                )

                if state.noalert:
                    terminal = descendant_terminal
                    selected = self.domain.bottom()
                    dropped = self.domain.bottom()
                else:
                    terminal = matched
                    if wazuh_runtime_level(state.load_priority) == 0:
                        selected = self.domain.bottom()
                        dropped = self_region
                    else:
                        selected = self_region
                        dropped = self.domain.bottom()

                shadowed = self.domain.difference(
                    candidate,
                    matched,
                )

                facts[occurrence_id] = OccurrenceFacts(
                    candidate=candidate,
                    reached=reached,
                    matched=matched,
                    terminal=terminal,
                    selected=selected,
                    dropped=dropped,
                    shadowed=shadowed,
                )

                selected_by_rule[occurrence.rule_id] = self.domain.union(
                    selected_by_rule.get(
                        occurrence.rule_id,
                        self.domain.bottom(),
                    ),
                    selected,
                )
                dropped_by_rule[occurrence.rule_id] = self.domain.union(
                    dropped_by_rule.get(
                        occurrence.rule_id,
                        self.domain.bottom(),
                    ),
                    dropped,
                )

                residual = self.domain.difference(residual, terminal)

                queue.append(
                    (
                        occurrence_id,
                        matched,
                        candidate,
                    )
                )

        return AssessmentResult(
            facts=facts,
            termination=termination,
            selected_by_rule=selected_by_rule,
            dropped_by_rule=dropped_by_rule,
        )
