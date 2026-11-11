"""Compared RuleVis predictions with independently captured Wazuh 4.14.10 data.

Use --predictions for model-only inspection; this is NOT a native oracle.
Use --oracle only with output from a separately instrumented/compiled analysisd.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from internal.differential import (
    compare_suite, load_fixture, normalize_snapshot, predict,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture", required=True, type=Path,
        help="Version-pinned JSON scenario definitions",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--predictions", action="store_true",
        help="Emit RuleVis model output only, NOT runtime verification",
    )
    mode.add_argument(
        "--oracle", type=Path,
        help="JSON observations collected separately from compiled analysisd",
    )
    parser.add_argument("--output", type=Path, help="Write JSON instead of stdout")
    args = parser.parse_args(argv)

    try:
        fixture, digest = load_fixture(args.fixture)
        if args.predictions:
            result = {
                "schema_version": 1,
                "wazuh_version": "4.14.10",
                "basis": "rulevis_prediction_not_native_verification",
                "fixture_sha256": digest,
                "scenarios": {
                    case["id"]: normalize_snapshot(predict(case))
                    for case in fixture["scenarios"]
                },
            }
        else:
            oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
            result = compare_suite(fixture, digest, oracle)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Differential input error: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output is None:
        print(output, end="")
    else:
        args.output.write_text(output, encoding="utf-8")
    return 1 if result.get("status") == "divergence" else 0


if __name__ == "__main__":
    raise SystemExit(main())
