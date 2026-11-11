# Wazuh 4.14.10 differential validation

This directory defines a **comparison protocol**, not a claim of completed
runtime verification. RuleVis predicts structural accepted rules, physical
attachments and historical SID/group subscriptions. A separate, instrumented
**compiled Wazuh 4.14.10** process must supply the observed oracle.

The initial fixture suite covers pre-existing and forward SID references,
late group sources, rejected consumers, dual-history sources, multiple physical
occurrences, group overwrites, missing-base overwrites, selector precedence,
and forward structural group attachments.

## Running the model side

From the repository root after installing the project (for example,
`python -m pip install -e ".[test]"`):

```shell
PYTHONPATH=src python scripts/compare_wazuh_41410.py --fixture tests/fixtures/wazuh_41410_differential.json --predictions --output /tmp/rulevis-predictions.json
PYTHONPATH=src python scripts/render_wazuh_41410_rules.py --fixture tests/fixtures/wazuh_41410_differential.json --out-dir /tmp/rulevis-native-rules
```

The first command outputs `basis=rulevis_prediction_not_native_verification`.
The second creates one ordered XML ruleset per scenario. **Do not install
these rules on a production Wazuh manager.** The fixtures include synthetic
template IDs below 10, overwrite experiments, and deliberate invalid references.
Use a disposable, fully isolated test environment.

## Capturing the native oracle

An opt-in native GDB probe and provenance-bound assembler are now available.
See [Native Oracle Capture](wazuh-41410-native-oracle-capture.md) for the
isolated debugger workflow. The capture infrastructure is not evidence that
a compiled Wazuh manager has been executed in CI.



Use the exact Wazuh 4.14.10 source and a compiled manager test installation.
For each fixture, configure a fresh ruleset and record the tree *after* the
loader has processed the declaration sequence. Native instrumentation must
report:

* `accepted_rules`: unique accepted logical rule IDs;
* `attachments`: counts of physical `RuleNode` child attachments grouped by
  parent rule ID, child rule ID, and effective structural relationship;
* `registrations`: `if_matched_sid` and `if_matched_group` subscriptions
  grouped by source rule ID, consumer rule ID and relation type. Count SID
  history **once per shared source RuleInfo list**, even if multiple physical
  nodes reference it. Count group-history appends at physical occurrence
  granularity, including duplicates.

The native collector should inspect `OS_MarkID()` and `OS_MarkGroup()` with
the actual `RuleInfo` pointers and `RuleNode` traversal. Merely collecting
CLI alert outputs is **not** an equivalent oracle: rule selection, thresholds,
and event histories also influence alerts. `wazuh-analysisd -t` can check
configuration acceptance, and `wazuh-logtest` can supply complementary
black-box event fixtures, but neither directly reports history-list pointers.

A supported native oracle is a JSON file shaped like:

```json
{
  "schema_version": 1,
  "provenance": {
    "engine": "compiled_wazuh_analysisd",
    "wazuh_version": "4.14.10",
    "fixture_sha256": "<SHA-256 of exact fixture JSON bytes>",
    "binary_sha256": "<SHA-256 of instrumented binary>",
    "ruleset_config_sha256": "<SHA-256 of exact native configuration>",
    "capture_method": "<native probe description>"
  },
  "scenarios": {
    "sid-existing": {
      "accepted_rules": [],
      "attachments": [],
      "registrations": []
    }
  }
}
```

The example is **schema illustration only**, not observational data.
The actual oracle must include all scenario IDs from the fixture JSON, with
all three result arrays populated from independent native observations. For
each attachment row, provide `parent_rule_id`, `child_rule_id`,
`relation_type`, `count`. For each registration row provide
`source_rule_id`, `consumer_rule_id`, `relation_type`, `count`.
The comparison contract rejects missing/duplicate rows, differing fixture
digests, unrecognized versions, and incomplete scenario coverage.

```shell
PYTHONPATH=src python scripts/compare_wazuh_41410.py --fixture tests/fixtures/wazuh_41410_differential.json --oracle /path/to/native-observations.json --output /tmp/rulevis-differential.json
```

Exit codes: 0 for identical snapshots, 1 for one or more divergences, and 2
for invalid input or provenance. The report retains every divergence by
scenario and data type, rather than stopping on the first mismatch.

## Evidence boundary and remaining steps

The comparison protocol **does not collect a native oracle by itself**.
The SHA-256 fields bind the reported observations to declared artifacts when
the collector computes them correctly; they are metadata checks, not a proof
of execution or a substitute for inspecting the collecting program. Runtime
equivalence remains **unverified** until native observations are captured,
audited and compared.

Implementation work still required: execute the debugger probe against
a compiled Wazuh 4.14.10 loader in a disposable test environment, capture
immutable oracle artifacts;
validate any loader/registration divergences; add tests for event insertion,
search, expiration and cleanup; and only then promote the registration model
to runtime-verified evidence. None of this changes RuleVis's declared graph
or the existing advisory UI.
