from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Union

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
                affected_events=domain.cardinality(finding.region),
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
                candidate_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "candidate",
                    )
                ),
                reached_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "reached",
                    )
                ),
                matched_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "matched",
                    )
                ),
                selected_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "selected",
                    )
                ),
                dropped_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "dropped",
                    )
                ),
                shadowed_events=domain.cardinality(
                    _union_regions(
                        occurrence_ids,
                        result,
                        "shadowed",
                    )
                ),
                findings=tuple(findings_by_rule.get(rule_id, ())),
            )
        )

    return AssessmentReport(
        schema_version=1,
        event_count=domain.event_count,
        rules=tuple(rules),
        issues=model.issues,
    )


def assessment_report_to_dict(report: AssessmentReport) -> dict[str, object]:
    """Convert a report to a stable JSON-compatible representation."""
    return {
        "schema_version": report.schema_version,
        "event_count": report.event_count,
        "rules": [
            {
                "rule_id": rule.rule_id,
                "occurrence_count": rule.occurrence_count,
                "candidate_events": rule.candidate_events,
                "reached_events": rule.reached_events,
                "matched_events": rule.matched_events,
                "selected_events": rule.selected_events,
                "dropped_events": rule.dropped_events,
                "shadowed_events": rule.shadowed_events,
                "findings": [
                    {
                        "kind": finding.kind.value,
                        "occurrence_id": finding.occurrence_id,
                        "affected_events": finding.affected_events,
                        "witness": {
                            "event_index": finding.witness.event_index,
                            "occurrence_path": list(
                                finding.witness.occurrence_path
                            ),
                            "blocking_occurrence": (
                                finding.witness.blocking_occurrence
                            ),
                        },
                    }
                    for finding in rule.findings
                ],
            }
            for rule in report.rules
        ],
        "issues": [
            {
                "code": issue.code,
                "rule_id": issue.rule_id,
                "selector": issue.selector,
            }
            for issue in report.issues
        ],
    }


def write_assessment_report(
    report: AssessmentReport,
    path: Union[str, Path],
) -> None:
    """Write deterministic, versioned assessment JSON."""
    Path(path).write_text(
        json.dumps(
            assessment_report_to_dict(report),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
