from __future__ import annotations

from dataclasses import dataclass

from internal.assessment import (
    AssessmentFinding,
    AssessmentResult,
    FindingKind,
    FindingWitness,
)
from internal.domains import BitsetDomain
from internal.evaluation import EvaluationModel, LoadIssue


@dataclass(frozen=True)
class FindingSummary:
    kind: FindingKind
    occurrence_id: int
    affected_events: int
    witness: FindingWitness


@dataclass(frozen=True)
class RuleAssessment:
    rule_id: str
    occurrence_count: int
    candidate_events: int
    reached_events: int
    matched_events: int
    selected_events: int
    dropped_events: int
    shadowed_events: int
    findings: tuple[FindingSummary, ...]


@dataclass(frozen=True)
class AssessmentReport:
    schema_version: int
    event_count: int
    rules: tuple[RuleAssessment, ...]
    issues: tuple[LoadIssue, ...]


def _union_regions(
    occurrence_ids: tuple[int, ...],
    result: AssessmentResult,
    attribute: str,
) -> int:
    region = 0
    for occurrence_id in occurrence_ids:
        region |= getattr(result.facts[occurrence_id], attribute)
    return region


def build_assessment_report(
    model: EvaluationModel,
    domain: BitsetDomain,
    result: AssessmentResult,
    findings: tuple[AssessmentFinding, ...],
) -> AssessmentReport:
    """Build the stable assessment-facing model from evaluator internals."""
    findings_by_rule: dict[str, list[FindingSummary]] = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(
            FindingSummary(
                kind=finding.kind,
                occurrence_id=finding.occurrence_id,
                affected_events=finding.region.bit_count(),
                witness=finding.witness,
            )
        )

    rules: list[RuleAssessment] = []
    for rule_id in model.rules:
        occurrence_ids = model.occurrences_by_rule.get(rule_id, ())
        rules.append(
            RuleAssessment(
                rule_id=rule_id,
                occurrence_count=len(occurrence_ids),
                candidate_events=_union_regions(
                    occurrence_ids,
                    result,
                    "candidate",
                ).bit_count(),
                reached_events=_union_regions(
                    occurrence_ids,
                    result,
                    "reached",
                ).bit_count(),
                matched_events=_union_regions(
                    occurrence_ids,
                    result,
                    "matched",
                ).bit_count(),
                selected_events=_union_regions(
                    occurrence_ids,
                    result,
                    "selected",
                ).bit_count(),
                dropped_events=_union_regions(
                    occurrence_ids,
                    result,
                    "dropped",
                ).bit_count(),
                shadowed_events=_union_regions(
                    occurrence_ids,
                    result,
                    "shadowed",
                ).bit_count(),
                findings=tuple(findings_by_rule.get(rule_id, ())),
            )
        )

    return AssessmentReport(
        schema_version=1,
        event_count=domain.event_count,
        rules=tuple(rules),
        issues=model.issues,
    )
