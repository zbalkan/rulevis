"""Wazuh 4.14.10 historical-registration projection, separate from UI edges.

OS_MarkID and OS_MarkGroup inspect the RuleNode tree immediately after a
consumer is inserted. Later sources are not registered retroactively.
Registrations are snapshots: overwrites can change source metadata but do
not replay the original consumer's registration.
"""

from __future__ import annotations

from dataclasses import dataclass

from internal.catalog import RuleCatalog, RuleDeclaration, os_match, select_historical_search
from internal.evaluation import EvaluationBuilder, EvaluationModel
from internal.historical_group_index import HistoricalGroupMembershipIndex


@dataclass(frozen=True)
class HistoricalRegistration:
    """One matched physical source occurrence at consumer registration time."""

    source_rule_id: str
    source_occurrence_id: int
    consumer_rule_id: str
    selector: str
    relation_type: str
    consumer_declaration_sequence: int
    source_group_at_registration: str


@dataclass(frozen=True)
class HistoricalRegistrationProjection:
    """Historical subscriptions captured during the modeled loader sequence."""

    structural_model: EvaluationModel
    registrations: tuple[HistoricalRegistration, ...]

    def subscriptions_for_source(self, source_rule_id: str) -> tuple[HistoricalRegistration, ...]:
        return tuple(
            entry for entry in self.registrations
            if entry.source_rule_id == source_rule_id
        )

    def subscribers(self, source_rule_id: str, relation_type: str) -> tuple[str, ...]:
        return tuple(sorted({
            entry.consumer_rule_id for entry in self.registrations
            if entry.source_rule_id == source_rule_id
            and entry.relation_type == relation_type
        }))

    def dual_history_sources(self) -> tuple[str, ...]:
        """Sources for which SID-first event insertion can bypass group lists."""
        by_source: dict[str, set[str]] = {}
        for entry in self.registrations:
            by_source.setdefault(entry.source_rule_id, set()).add(entry.relation_type)
        return tuple(sorted(
            source for source, kinds in by_source.items()
            if {"if_matched_sid", "if_matched_group"} <= kinds
        ))


class HistoricalRegistrationBuilder:
    """Capture registrations as accepted rules enter the occurrence tree.

    A source can have multiple physical RuleNode occurrences. Records retain
    this multiplicity, particularly important for OS_MarkGroup, which can
    append the same consumer group-search list more than once. Subscribers()
    and dual_history_sources() collapse to logical RuleInfo identity.
    """

    def __init__(self, catalog: RuleCatalog, *, max_occurrences: int = 100_000) -> None:
        self.catalog = catalog
        self.max_occurrences = max_occurrences
        self._registrations: list[HistoricalRegistration] = []
        self._built = False
        self._groups = HistoricalGroupMembershipIndex(
            declaration.if_matched_group
            for declaration in catalog.declarations
            if select_historical_search(
                declaration.if_matched_sid,
                declaration.if_matched_group,
            ) == "if_matched_group"
            and not declaration.overwrite
        )

    def _on_group_change(self, rule_id: str, group: str | None) -> None:
        if group is None:
            self._groups.discard(rule_id)
        else:
            self._groups.update(rule_id, group)

    def _candidate_occurrences(
        self, selector: str, search: str, builder: EvaluationBuilder,
    ) -> list[int]:
        """Sort only matching physical occurrences in current RuleNode order."""
        source_rules = (
            (selector,) if search == "if_matched_sid"
            else self._groups.matching_rules(selector)
        )
        matches = (
            occurrence_id
            for rule_id in source_rules
            for occurrence_id in builder.occurrences_by_rule.get(rule_id, ())
        )
        return sorted(
            matches,
            key=lambda occurrence_id: builder.order.rank(
                builder.enter_token_by_occurrence[occurrence_id]
            ),
        )

    def _on_accepted(self, declaration: RuleDeclaration, builder: EvaluationBuilder) -> None:
        # rules.c guards both OS_MarkID and OS_MarkGroup with !DO_OVERWRITE,
        # even when the requested overwrite had no existing RuleInfo.
        if declaration.overwrite:
            return
        search = select_historical_search(
            declaration.if_matched_sid, declaration.if_matched_group,
        )
        if search is None:
            return
        selector = (
            str(declaration.if_matched_sid)
            if search == "if_matched_sid"
            else declaration.if_matched_group
        )
        if selector is None:
            return

        # Native OS_MarkID and OS_MarkGroup traverse the current RuleNode
        # tree. Index candidate RuleInfo objects first, then order their
        # physical occurrences by current preorder rank. This retains native
        # registration order without scanning unrelated occurrences.
        for occurrence_id in self._candidate_occurrences(
            selector, search, builder,
        ):
            occurrence = builder.occurrences[occurrence_id]
            source = builder.rules[occurrence.rule_id]
                self._registrations.append(HistoricalRegistration(
                    source_rule_id=source.rule_id,
                    source_occurrence_id=occurrence_id,
                    consumer_rule_id=declaration.rule_id,
                    selector=selector,
                    relation_type=search,
                    consumer_declaration_sequence=declaration.sequence,
                    source_group_at_registration=source.runtime_group,
                ))

    def build(self) -> HistoricalRegistrationProjection:
        if self._built:
            raise RuntimeError("HistoricalRegistrationBuilder instances can only build once")
        self._built = True
        builder = EvaluationBuilder(
            self.catalog,
            max_occurrences=self.max_occurrences,
            on_accepted=self._on_accepted,
            on_group_change=self._on_group_change,
        )
        model = builder.build()
        return HistoricalRegistrationProjection(
            structural_model=model,
            registrations=tuple(self._registrations),
        )


def build_historical_registrations(
    catalog: RuleCatalog, *, max_occurrences: int = 100_000,
) -> HistoricalRegistrationProjection:
    """Build a new independent source-faithful registration projection."""
    return HistoricalRegistrationBuilder(
        catalog, max_occurrences=max_occurrences,
    ).build()
