# Wazuh 4.14.10 differential validation

The differential protocol compares RuleVis predictions with independent
observations from a **compiled Wazuh 4.14.10** analysisd process. It checks
accepted logical rules, physical structural attachments and historical
SID/group registrations, with binary, fixture and loaded-file provenance.
The initial ten scenarios passed in GitHub Actions run 43085696078.
This phase extends the same native oracle to four incremental-SID
scenarios; these additions require separate native verification.

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

The CI suite runner collects a native oracle under GDB. SHA-256 provenance
fields bind observations to the captured binary, rules and configuration;
they are metadata checks, not cryptographic attestation. Inspect the
capturing program and logs before interpreting results as verified evidence.

The ten original scenarios have independent native-loader/registration
agreement. The four additional SID scenarios must pass before the
expanded loader-fidelity claim is accepted. Future work must still test
actual event insertion, SID/group history search, expiry and cleanup;
structural registration alone does not prove alert delivery or parity
of the runtime event processor. RuleVis's declared graph and advisory
UI remain separate from these experimental predictions.
