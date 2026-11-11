"""Compared indexed history registration with the original full-preorder scan.

Example:
PYTHONPATH=src python benchmarks/historical_registration_scaling.py --rules 1000 --consumers 250

No performance thresholds are enforced in CI. The reference implementation
is an independent full-scan lookup and is used to check identical results.
"""
from __future__ import annotations

import argparse
import statistics
import time
import tracemalloc

from internal.catalog import RuleCatalog, os_match
from internal.historical_registration import (
    HistoricalRegistrationBuilder,
    build_historical_registrations,
)


class FullScanReference(HistoricalRegistrationBuilder):
    def _candidate_occurrences(self, selector, search, builder):
        return [
            occurrence_id
            for occurrence_id in builder._occurrences_in_preorder()
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


def catalog_for(rules: int, consumers: int, matched_percent: int) -> RuleCatalog:
    if not 0 <= matched_percent <= 100:
        raise ValueError("matched_percent must be between 0 and 100")
    catalog = RuleCatalog()

    def add(rule_id, *, group, sid=None, matched_group=None, matched_sid=None):
        catalog.append(
            rule_id=str(rule_id), file="benchmark.xml",
            source_level=5, accuracy=1, noalert=False, overwrite=False,
            runtime_group=group, display_groups=[], category="syslog",
            if_sid=sid, if_level=None, if_group=None,
            if_matched_sid=matched_sid, if_matched_group=matched_group,
            conditions=[], temporal_conditions=[],
        )

    add(1, group="root,")
    for i in range(rules):
        add(
            100000 + i, sid="1",
            group="matching," if (i * 100) // max(rules, 1) < matched_percent
            else "unrelated,",
        )
    for i in range(consumers):
        if i % 2:
            add(700000 + i, sid="1", matched_sid=100000)
        else:
            add(700000 + i, sid="1", matched_group="matching")
    return catalog


def measure(fn, repeats):
    times = []
    peaks = []
    result = None
    for _ in range(repeats):
        tracemalloc.start()
        start = time.perf_counter()
        try:
            result = fn()
            times.append(time.perf_counter() - start)
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
    return result, statistics.median(times), max(peaks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=int, default=1000)
    parser.add_argument("--consumers", type=int, default=250)
    parser.add_argument("--matched-percent", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if min(args.rules, args.consumers, args.repeats) < 1:
        parser.error("rules, consumers and repeats must be positive")
    if not 0 <= args.matched_percent <= 100:
        parser.error("matched-percent must be 0..100")
    if args.rules + args.consumers + 1 > 100000:
        parser.error("scenario exceeds the default occurrence budget")
    catalog = catalog_for(args.rules, args.consumers, args.matched_percent)
    before, old_time, old_peak = measure(
        lambda: FullScanReference(catalog).build(), args.repeats,
    )
    after, new_time, new_peak = measure(
        lambda: build_historical_registrations(catalog), args.repeats,
    )
    if before.registrations != after.registrations:
        raise AssertionError("Registration semantics diverged")
    print(f"Rules: {args.rules}; consumers: {args.consumers}; matched: {args.matched_percent}%")
    print(f"Records: {len(after.registrations)}")
    print(f"Full scan: {old_time:.4f}s; peak tracked allocation: {old_peak:,} bytes")
    print(f"Indexed:   {new_time:.4f}s; peak tracked allocation: {new_peak:,} bytes")
    print(f"Time ratio (full/indexed): {old_time / new_time:.2f}x")


if __name__ == "__main__":
    main()
