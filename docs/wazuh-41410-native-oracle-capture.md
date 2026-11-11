# Capturing a native Wazuh 4.14.10 differential oracle

This is an **experimental Linux/GDB probe**. It inspects a compiled, debug-symbol
Wazuh 4.14.10 `wazuh-analysisd` process at the first top-level `_setlevels()`
entry point. Wazuh has finished loading the initial rule tree at that point,
before level normalization. The probe reads `RuleNode`, `RuleInfo`,
`sid_prev_matched`, `sid_search`, `group_prev_matched`, and `group_search`
directly from inferior process memory.

It is **not** suitable for production. Debug the binary on a disposable
manager with a fresh configuration for each scenario. Do not modify a running
production manager or its actual ruleset to reproduce these tests.

## Prerequisites

Use the exact Wazuh `4.14.10` source, compiled with accessible debug symbols
(`-g`, preferably without optimization). Verify the source and binary
identity independently. GDB's embedded Python must be available. The
`_setlevels(RuleNode *node, int nnode)` entry point must retain readable
`node` and `nnode` parameters.

A separate isolated analysisd configuration is required for **each** fixture.
Only the fixture rules, not stock/custom production rules, may be loaded.
The probe records all native rule IDs and the assembler refuses any snapshot
with unexpected IDs. Ensure the manager's effective include order precisely
matches the scenario and that Wazuh accepts the XML. Generated fixtures
include intentional invalid references and overwrite cases; a rejected
declaration need not prevent the other declarations from loading.

## End-to-end suite runner (isolated manager only)

The optional `scripts/run_wazuh_41410_suite.py` orchestrates the pinned
scenarios sequentially, retaining configuration copies, captured native
snapshots, preparation logs, debugger logs, and the final differential report.
**It does not provision a Wazuh manager.** A trusted operator-supplied
executable must install each scenario in an independently isolated
4.14.10 test installation. Do not point it at a production manager.

The preparation executable receives three positional arguments:
`<scenario-id> <rendered-rules.xml> <evidence-config-dir>`. It must install
the fixture as the isolated manager's **only** loaded ruleset and write copies
of the actually deployed rules to `<evidence-config-dir>/rules.xml` and the
effective configuration to `<evidence-config-dir>/ossec.conf`. It must exit
nonzero when installation or isolation verification fails. The suite runner
verifies the rules copy equals the rendered fixture before starting GDB.
**The runner cannot establish that the manager actually loaded the submitted
configuration; the preparation executable and its environment must be
audited independently.**

Use a new empty evidence destination for every invocation. For example:

```shell
PYTHONPATH=src python scripts/run_wazuh_41410_suite.py --fixture tests/fixtures/wazuh_41410_differential.json --binary /path/to/isolated/wazuh-analysisd --workspace /tmp/rulevis-native-run-01 --preparer /path/to/your/isolated-scenario-installer --cwd /path/to/isolated/manager
```

The runner exits 0 when all compared snapshots match, 1 for differences,
and 2 for missing prerequisites, failed preparation, invalid captures or
other incomplete validation. A nonzero preparation or capture error stops
the suite; partial evidence remains in the workspace for diagnosis.
The pipeline neither changes `master` nor publishes oracle artifacts.
Do not interpret synthetic unit tests as native observations.

## Capture one scenario

Install RuleVis dependencies, then render the pinned scenarios:

```shell
PYTHONPATH=src python scripts/render_wazuh_41410_rules.py --fixture tests/fixtures/wazuh_41410_differential.json --out-dir /tmp/rulevis-native-rules
```

For `sid-existing`, place the exact contents of
`/tmp/rulevis-native-rules/sid-existing.xml` in the isolated manager's
configured rules include. Make a byte-for-byte copy of the deployed rules
file as `/tmp/rulevis-native-configs/sid-existing/rules.xml` and copy its
effective `ossec.conf` as
`/tmp/rulevis-native-configs/sid-existing/ossec.conf`.
Copies are evidence inputs, not replacements for the actual deployed files.

Create the capture directory and run the compiled analysisd test binary
under GDB. The wrapper launches the binary with `-t` by default:

```shell
PYTHONPATH=src python scripts/run_wazuh_41410_gdb.py --fixture tests/fixtures/wazuh_41410_differential.json --scenario sid-existing --binary /var/ossec/bin/wazuh-analysisd --output /tmp/rulevis-native-captures/sid-existing.json
```

The wrapper requires the output directory to exist, refuses overwrites,
rejects a missing breakpoint capture, and checks the resulting envelope.
If the binary exits before reaching `_setlevels`, no usable oracle exists.
Failures do not silently fall back to model predictions.

Restore the isolated manager to a clean state, install the **next** scenario,
and repeat the process for every scenario in the pinned JSON suite. Do not
reuse an analysisd process or loaded state across scenarios.

## Assemble and compare

After every scenario has a successful GDB capture and a matching native
configuration snapshot, assemble a single oracle:

```shell
PYTHONPATH=src python scripts/assemble_wazuh_41410_oracle.py --fixture tests/fixtures/wazuh_41410_differential.json --captures /tmp/rulevis-native-captures --configs /tmp/rulevis-native-configs --binary /var/ossec/bin/wazuh-analysisd --output /tmp/rulevis-native-oracle.json
```

Then compare it with RuleVis predictions:

```shell
PYTHONPATH=src python scripts/compare_wazuh_41410.py --fixture tests/fixtures/wazuh_41410_differential.json --oracle /tmp/rulevis-native-oracle.json --output /tmp/rulevis-differential-report.json
```

The assembler calculates binary SHA-256, exact fixture SHA-256, and a
deterministic aggregate SHA-256 of per-scenario configuration-file hashes.
It also rejects unexpected native rule IDs, missing scenarios, inconsistent
scenario labels, and modified rules XML.

## What is and is not independent

Native process memory supplies **physical** rule-node identities, accepted
rule IDs, parent-child placements, SID-list pointer aliasing, and group-list
pointer multiplicities. The `relation_type` label for structural attachments
is derived from the scenario's first rule declaration, not recovered from a
native selector-provenance field. This limitation must be retained when
interpreting attachment comparisons. The probe does not claim to measure
historical event delivery, expiration, or alerts.

The `compiled_wazuh_analysisd` provenance marker indicates the intended
capture method, not cryptographic attestation. A supplied JSON file can be
forged. Review the native build, executable, deployed configuration, debugger
transcript and snapshot collection procedure before treating comparisons as
verified. The assembler's local copies cannot prove that the manager actually
used those files.

A full native oracle has **not** been produced in project CI. The CI tests
exercise the Python probe with mocked native pointers, the orchestration
wrapper with simulated subprocess behavior, and the schema/assembler with
synthetic comparison data. Actual Wazuh 4.14.10 differential validation
requires running these commands in the specified isolated native environment.
