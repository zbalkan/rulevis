#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from typing import Optional

from internal.assessment import AssessmentClassifier, BitsetAssessor
from internal.assessment_report import build_assessment_report
from internal.catalog import RuleCatalog
from internal.domains import BitsetDomain
from internal.evaluation import EvaluationBuilder


def add_rule(
    catalog: RuleCatalog,
    rule_id: int,
    level: int,
    *,
    if_sid: Optional[str] = None,
    if_group: Optional[str] = None,
    runtime_group: str = "bench,",
    category: Optional[str] = None,
) -> None:
    catalog.append(
        rule_id=str(rule_id),
        file="benchmark.xml",
        source_level=level,
        accuracy=1,
        noalert=False,
        overwrite=False,
        runtime_group=runtime_group,
        display_groups=[],
        category=category,
        if_sid=if_sid,
        if_level=None,
        if_group=if_group,
        if_matched_sid=None,
        if_matched_group=None,
        conditions=[],
        temporal_conditions=[],
    )


def wide_siblings(rule_count: int) -> RuleCatalog:
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="bench")
    for offset in range(rule_count):
        add_rule(
            catalog,
            100000 + offset,
            5,
            if_sid="1",
        )
    return catalog


def deep_chain(rule_count: int) -> RuleCatalog:
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="bench")
    parent = "1"
    for offset in range(rule_count):
        rule_id = 100000 + offset
        add_rule(
            catalog,
            rule_id,
            5,
            if_sid=parent,
        )
        parent = str(rule_id)
    return catalog


def group_fanout(rule_count: int) -> RuleCatalog:
    catalog = RuleCatalog()
    add_rule(catalog, 1, 0, category="bench")
    for offset in range(rule_count):
        add_rule(
            catalog,
            100000 + offset,
            5,
            if_sid="1",
            runtime_group="bench,shared,",
        )
    add_rule(
        catalog,
        900000,
        6,
        if_group="shared",
    )
    return catalog


SCENARIOS: dict[str, Callable[[int], RuleCatalog]] = {
    "wide": wide_siblings,
    "deep": deep_chain,
    "group": group_fanout,
}


def benchmark(
    scenario: str,
    rule_count: int,
    event_count: int,
) -> tuple[float, float, float, float, int, int]:
    catalog = SCENARIOS[scenario](rule_count)

    started = time.perf_counter()
    model = EvaluationBuilder(catalog).build()
    built = time.perf_counter()

    domain = BitsetDomain(event_count)
    predicates = {"1": domain.top()}
    result = BitsetAssessor(model, domain, predicates).assess()
    assessed = time.perf_counter()

    findings = AssessmentClassifier(model, result).classify()
    classified = time.perf_counter()

    report = build_assessment_report(
        model,
        domain,
        result,
        findings,
    )
    reported = time.perf_counter()

    return (
        built - started,
        assessed - built,
        classified - assessed,
        reported - classified,
        len(model.occurrences),
        len(report.rules),
    )


def comma_ints(value: str) -> list[int]:
    return [int(part) for part in value.split(",") if part]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark source-faithful assessment scaling.",
    )
    parser.add_argument(
        "--scenario",
        choices=tuple(SCENARIOS),
        default="wide",
    )
    parser.add_argument(
        "--rules",
        type=comma_ints,
        default=[100, 1000, 5000],
        help="Comma-separated logical rule counts.",
    )
    parser.add_argument(
        "--events",
        type=comma_ints,
        default=[64, 1024, 8192],
        help="Comma-separated finite-domain event counts.",
    )
    args = parser.parse_args()

    print(
        "scenario,rules,events,occurrences,report_rules,"
        "build_s,assess_s,classify_s,report_s"
    )
    for rule_count in args.rules:
        for event_count in args.events:
            (
                build_s,
                assess_s,
                classify_s,
                report_s,
                occurrences,
                report_rules,
            ) = benchmark(
                args.scenario,
                rule_count,
                event_count,
            )
            print(
                f"{args.scenario},{rule_count},{event_count},"
                f"{occurrences},{report_rules},"
                f"{build_s:.6f},{assess_s:.6f},"
                f"{classify_s:.6f},{report_s:.6f}"
            )


if __name__ == "__main__":
    main()
