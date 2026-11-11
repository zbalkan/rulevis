# Source-Faithful Rule Assessment

## Status

This is an experimental analysis subsystem. It is intentionally independent
from RuleVis's visualization graph, Flask APIs, and JavaScript UI.

The implementation targets the Wazuh 4.14.10 rule-loader and RuleNode
construction behavior represented by `rules.c` and `rules_list.c`. The goal
is not to emulate every Wazuh runtime feature. The goal is to reconstruct the
structural evaluation order faithfully enough that later reachability and
shadowing analysis is based on the same rule occurrences and ordering Wazuh
would build.

## Architecture

```text
Rule XML
   |
   v
RuleCatalog
   |
   v
EvaluationBuilder
   |
   v
Runtime occurrence DAG
   |
   +---- supplied finite-domain predicates
   v
BitsetAssessor
   |
   v
AssessmentClassifier
   |
   v
AssessmentReport
   |
   v
Versioned JSON
```

The layers have separate responsibilities:

- `RuleCatalog` preserves source load order and the declaration data required
  to replay Wazuh loading, including overwrites and parent selectors.
- `EvaluationBuilder` creates logical rule state plus every runtime
  occurrence of a rule. It does not use the visualization graph as an
  execution model.
- `BitsetDomain` represents a finite event universe with Python integer
  bitsets.
- `BitsetAssessor` performs exact set evaluation over that supplied universe.
- `AssessmentClassifier` interprets occurrence facts without recomputing
  evaluation.
- `AssessmentReport` converts internal bitsets into counts and deterministic
  witnesses suitable for external consumers.
- JSON serialization is versioned and excludes raw internal bitsets.

## Wazuh load semantics represented

The builder intentionally mirrors several behaviors that are easy to
mis-model:

- an omitted category defaults to `syslog`;
- level 0 is encoded as priority 9900 during ordinary loading when accuracy is
  enabled;
- `if_level` compares against encoded load-time priority, before Wazuh's
  later `_setlevels()` normalization;
- `accuracy="0"` leaves the source level unscaled during ordering;
- overwriting a rule mutates its effective priority but does not reposition
  existing RuleNode occurrences;
- an overwrite whose target does not exist is processed as an ordinary rule;
- `if_group` is one Wazuh `OS_WordMatch` expression, including pipe
  alternatives, not a comma-separated selector list;
- nested group wrappers contribute to the runtime group string;
- rule IDs and SID references use the same numeric canonicalization;
- `if_sid` attachment follows current recursive RuleNode preorder and honors
  Wazuh's early return within a sibling-list invocation;
- one logical rule can therefore have multiple runtime occurrences.

These semantics are separate from the condition-path visualization.
The UI graph includes declared `if_level` dependencies, including later
and superseded references, because RuleVis is also a source-analysis tool.
The evaluator instead models attachments to accepted rule occurrences in
current Wazuh tree order.

## Logical relationship projection

`project_occurrence_relationships(EvaluationBuilder(catalog).build())`
projects accepted physical `RuleNode` occurrences onto logical rule IDs.
Every edge retains its originating relationship type, selector, and the
number of physical attachments it represents. Implicit category-based
attachments are labeled `category`; synthesized temporal parents retain
their `if_matched_sid` or `if_matched_group` origin. This graph can be
compared with `GraphGenerator.G` without deleting declared-only edges or
cycles from static analysis.

Temporal selectors can describe two distinct relationships. When no explicit
structural parent is provided, analysisd synthesizes `if_sid` or `if_group`
before attachment. Subsequent `OS_MarkID` or `OS_MarkGroup` registers
historical sources separately. The visualization graph shows both a
structural edge (marked `synthesized_from`) and a declared temporal
reference, while the occurrence projection contains only structural
attachments.

The occurrence graph itself must remain acyclic. Its logical projection
does not establish that a declared relation was available at load time
unless the corresponding accepted occurrences exist. The projection
does not model historical-event searches (`OS_MarkID`/`OS_MarkGroup`)
and does not validate arbitrary regex or field predicates.

Tests include mutual group dependencies analogous to stock Wazuh rules
80790/80791, level-threshold multiplicity, and missing-base overwrites.

## Opt-in modeled attachment projection (N2 foundation)

`GraphGenerator.build_modeled_runtime_projection(max_occurrences=100_000)`
is an explicit, potentially expensive bridge from parsed `RuleCatalog`
declarations to the occurrence evaluator. It stores a separate
`generator.modeled_runtime_graph` using
`project_occurrence_relationships()`, with per-edge attachment
`occurrence_count` and per-node accepted occurrence counts. It also
annotates the **declared** graph nodes with `modeled_acceptance`:
`accepted`, `rejected`, or `undeclared_reference` for placeholder
nodes introduced by missing dependency IDs. Presence of a declaration is
determined from the catalog, even if its invalid selector prevented a normal
visual node from being created. Each graph node also receives
`modeled_occurrence_count`, the number of physical RuleVis-modeled
occurrences for that rule (zero for rejected or undeclared references).
`modeled_load_issues` on graph nodes contains issues for that node, while
`generator.modeled_load_issues` contains the complete ordered modeled
load-issue output, including declarations that never created graph nodes.
Each global record contains `rule_id`, `code`, and `selector`.

This method is **not** invoked during ordinary XML graph generation.
It does not replace source edges, rewrite candidate snapshots, change
Flask graph presentation, or claim that Wazuh accepted any rule.
`accepted` here means *accepted by RuleVis's occurrence model*, not
confirmed by a running Wazuh manager. The configured manager include
order and runtime loader may differ from RuleVis's file scan. A model
occurrence-budget exception leaves the previously published projection
unchanged. The N2 issue requires version-pinned differential tests
before presenting this model as verified effective runtime attachment.



## Indexed historical registration lookup

The opt-in historical-registration projection no longer builds a complete
`RuleNode` preorder snapshot for every accepted historical consumer.
`if_matched_sid` resolves candidates directly through the existing
`occurrences_by_rule` index. `if_matched_group` uses
`HistoricalGroupMembershipIndex`, a separate temporal `OSMatch` index;
it does **not** reuse structural `if_group`/`OS_WordMatch` membership.
Aho-Corasick and prefix matching generate a conservative superset of
positive group matches, then `os_match` confirms the exact result.
Negated selectors and empty alternatives receive fallback checks. Current
group membership is updated for every accepted rule and overwrite, with
failed declarations removed.

Only matching physical occurrences are ranked and sorted into current
`RuleNode` preorder. Each match still emits an independent provenance
record; repeated physical source occurrences and registration-time snapshots
remain intact. Existing full-scan equivalence tests cover mixed selectors,
multiple occurrences, late sources and overwrites.

For `k` matching physical occurrences among `V` total occurrences, the
lookup/sort stage costs approximately `O(k log V + k log k)`, plus index
candidate discovery. For common positive group patterns, index updates cost
time proportional to group-text length and candidate outputs. Negated
patterns and unselective patterns can still approach whole-ruleset work
because the underlying semantics legitimately match many sources.
The optimization avoids the previous unconditional `O(H × V)`
registration-time scanning pattern, where `H` is the number of historical
consumers. It does not guarantee linear total loader complexity.

Run the reproducible before/after benchmark (no enforced CI threshold):

```shell
PYTHONPATH=src python benchmarks/historical_registration_scaling.py --rules 1000 --consumers 250 --matched-percent 5
```

This is a RuleVis model optimization, **not** independent verification
against compiled Wazuh 4.14.10.

## Opt-in historical subscription projection (Wazuh 4.14.10)

`build_historical_registrations(catalog)` in
`internal.historical_registration` runs the existing `EvaluationBuilder`
with an accepted-declaration callback. Each callback observes the current
`RuleNode` occurrence tree immediately after insertion, matching the
registration point for `OS_MarkID()` and `OS_MarkGroup()` in
`src/analysisd/rules.c`. Rejected and duplicate declarations are not
registered; overwrites update existing rule state without replaying earlier
subscriptions. The loader's `DO_OVERWRITE` guard also suppresses registration
when an overwrite has no existing target and is inserted as a new rule.
A future source is not retroactively registered.

`HistoricalRegistrationProjection` returns the structural evaluation model
alongside immutable `HistoricalRegistration` records. Each record retains
source and consumer rule IDs, the physical source occurrence ID, selector,
relationship type, declaration sequence and source group string at registration
time. For `if_matched_group`, multiple physical source occurrences may produce
multiple registrations to the same group's history list. For
`if_matched_sid`, multiple occurrences share their source `RuleInfo` SID
list; per-occurrence records represent traversal evidence, **not** independent
SID history lists. The `subscribers()` helper deduplicates logical consumer
rule IDs and `dual_history_sources()` identifies sources where both SID and
group subscriptions were modeled.

The projection is **opt-in** and does not modify declared visualization edges,
Flask, the ordinary evaluation model or assessment reports. It models the
registration state, **not** historical event insertion, frequency/timeframe
matching, expiration, active response or alert outcomes. The SID-first event
insertion and mutually exclusive cleanup bugs remain uncorrected in Wazuh
4.14.10 and require a separate event-lifecycle model and compiled differential
fixtures before making runtime-verified claims. In particular, the model's
registration snapshot is only as faithful as the upstream structural
attachment and load-order model it consumes.

## Known upstream group-correlation limitations (Wazuh 4.14.10)

RuleVis flags potential gaps described in
[Wazuh issue #41279](https://github.com/wazuh/wazuh/issues/41279).
The warning banner appears when the graph includes relevant group dependencies.
Affected nodes receive amber markers and an explanation in the Details panel.
Warnings are also included as `correlation_warnings` in the node details API
and `correlation_warning_count` in the graph-node API.

The scan performs two conservative checks, using the existing declared graph:

- **GROUP_LOAD_ORDER / TEMPORAL_GROUP_LOAD_ORDER:** an `if_group` or
  `if_matched_group` source edge is present in the declared graph but is
  explicitly marked `load_order_candidate=false`. Both the source and
  dependent rule receive a warning. Shadowed selectors are excluded.
- **DUAL_HISTORY:** an earlier scanned source has a declared
  `if_matched_sid` subscriber and an eligible `if_matched_group`
  subscriber. Both the source and affected group consumers are warned that
  Wazuh 4.14.10's SID-first event insertion can bypass group history.

Each warning carries structured advisory metadata: `code`, `message`,
`basis=declared`, `phase`, `affected_rule_id`, sorted
`source_rule_ids`, `dependent_rule_ids`, `sid_subscriber_rule_ids`,
and `group_subscriber_rule_ids`, plus `dependent_modeled_acceptance`,
`relationship_status`, `wazuh_version`, and `upstream_issue`.
Rule identifiers retain the same role on source-side and dependent-side
warnings. `relationship_status=inactive_declaration` means all listed
dependents were explicitly rejected by the optional RuleVis loader model;
otherwise it remains `unverified`. This is distinct from verified runtime
registration and keeps rejected-declaration advisories visible. These fields preserve the original
UI's `code` and `message` contract. When an optional modeled projection is
present and marks a historical consumer rejected, that consumer is excluded
from inferred dual-history overlap. Rejected dependents can still carry a
declared load-order advisory explaining the potentially missing parent.
Neither case proves a real registration or a missed alert.

The rule details panel and conditions modal show the first three group chips
by default; further groups remain available through native expand/collapse
controls. This changes presentation only, not group values, matching, or APIs.
General upstream notices without rule-specific warnings use a subdued style.

These findings indicate **potential risks**, not confirmed runtime failures.
RuleVis does not reconstruct manager include order, rejected source nodes, or
`OS_MarkID`/`OS_MarkGroup` registrations during ordinary UI generation.
A missing warning is not proof of correct runtime correlation. The warnings
describe the Wazuh 4.14.10 implementation and should be reviewed when
targeting other Wazuh versions.

## Wazuh relationship sources

The model is checked against Wazuh 4.14.10's `rules.c`,
`rules_list.c`, `os_match_compile.c`, and `os_match_execute.c`.
The source-graph parser concatenates repeated `if_sid`, `if_level`,
`if_group`, and `if_matched_group` elements. By contrast,
`if_matched_sid` accepts one numeric value per element, with the last valid
value taking precedence; an invalid element rejects the rule in analysisd.
The parser uses `OSMatch` semantics for temporal group references
(different from `OS_WordMatch`), preserves `if_level` priority history,
and treats missing-base overwrites as new declarations at scan time.

As before, RuleVis's filesystem scanning is not equivalent to an
`ossec.conf`-selected include order. A source-level
`load_order_candidate` remains an estimate, not proof of a runtime
attachment. Differential tests against a compiled 4.14.10 loader are
still required before claiming byte- or occurrence-identical behavior.

### Incremental ordinary SID-list attachment

Wazuh 4.14.10 `OS_AddChild` resolves and attaches each ordinary `if_sid`
token immediately. A later token may therefore find a new physical
`RuleNode` occurrence created by an earlier token in the same rule.
Repetitions may create multiple occurrences under one parent. RuleVis
models this sequential behavior, including skipped nonexistent SID tokens.

The pinned native GDB oracle has four additional scenarios:
`sid-sequential-self`, `sid-repeated-token`,
`sid-missing-then-existing`, and `sid-existing-then-missing`.
A logical self-edge in the collapsed projection does not necessarily
imply a cycle in the physical occurrence graph.

**Boundary:** A nonzero `if_matched_sid` with multiple explicit
structural SID tokens can fail after partial native insertion. Wazuh's
failure cleanup may release a `RuleInfo` still referenced by a
physical node. RuleVis deliberately retains staged all-or-nothing
modeling for this unsafe rejection path, which is **not yet verified**
as a safe native observable state. This phase does not emulate
dangling references or crash behavior.

## Exact finite-domain evaluation

The assessor does not attempt arbitrary symbolic regex satisfiability.
Instead, the caller supplies a finite event universe and a bitset predicate for
each accepted logical rule. Missing predicates raise `ValueError` by default:
silently treating an omitted predicate as match-all can create false findings
about selection and shadowing.
When `event_count=0`, predicate coverage is vacuous: missing predicates are
permitted, because the universe contains no events to classify. This does not
relax coverage requirements for any nonempty domain. Tests or explicitly permissive analyses can
opt into `missing_predicate="match_all"`; that policy is an assumption, not
a property inferred from Wazuh rules.

For each runtime occurrence it records:

- `candidate`: events that would satisfy the occurrence if preceding siblings
  were ignored;
- `reached`: events still available when evaluation reaches the occurrence;
- `matched`: reached events satisfying the rule predicate;
- `terminal`: matched events for which the subtree returns a terminal result;
- `selected`: events for which this occurrence itself is selected;
- `dropped`: terminal events consumed by a level-0 occurrence;
- `shadowed`: candidate events removed before this occurrence can match.

`noalert` rules terminate only through descendants. This permits unmatched
regions to continue to later siblings, matching Wazuh's gate-like behavior.

## Finding classifications

Classification is occurrence-first. Logical-rule reports aggregate occurrence
counts only after the exact runtime analysis has completed.

- `never_candidate`: the rule's standalone predicate has no events in the
  supplied domain.
- `path_impossible`: the standalone predicate has events, but none survive
  the conjunction of predicates along this runtime occurrence path.
- `unreachable`: the occurrence has path-qualified candidate events, but no
  event reaches that point in its sibling list.
- `fully_shadowed`: events reach the sibling list, but all candidate events
  were consumed before this occurrence.
- `partially_shadowed`: some candidate events are consumed earlier while
  others still match.
- `dropped`: the occurrence consumes events through level-0 drop behavior.
- `never_selected`: the occurrence matches events but is never itself
  selected and is not classified as a level-0 drop. This includes `noalert`
  gates and regions fully consumed by descendants.

A finding carries the occurrence path and, when its affected region is
non-empty, a deterministic representative event. Findings with an empty region,
such as `never_candidate`, use `event_index = null`. An earlier blocking
occurrence is included when one can be identified. The witness is evidence for
the finding; it is not a second evaluation algorithm.

## Report contract

`AssessmentReport` is the boundary intended for future consumers. It contains:

- `schema_version`;
- finite-domain `event_count`;
- one deterministic logical-rule record per loaded rule;
- occurrence count;
- candidate, reached, matched, selected, dropped, and shadowed event counts;
- classified findings and witnesses;
- loader issues.

Raw bitsets remain internal. The JSON serializer emits counts and witness
identifiers only, making output stable, diffable, and independent from Python's
integer representation.

## Complexity

The design avoids pairwise all-rule comparison.

- `PrioritySequence` uses an augmented AVL tree. Insert, rank, indexed access,
  and priority update are `O(log N)`.
- `CategoryOrder` uses an augmented balanced tree with subtree category masks,
  giving logarithmic insertion, rank, category updates, and first-category
  lookup.
- group selector matching uses Aho-Corasick for unanchored alternatives and a
  prefix trie for anchored alternatives; matching logical rules are then
  consumed in current RuleNode preorder.
- SID occurrence resolution is output-sensitive and uses current order ranks;
  for `k` occurrences it is approximately `O(k log V + k log k)`.
- the two assessment graph passes are `O((V + E) * W)`, where `W` is the
  machine-word cost of the finite-domain bitsets.
- finding/report construction is output-sensitive. Witness paths necessarily
  cost at least the size of the explanation emitted.

The finite event-domain size is therefore an explicit scaling dimension. The
bitset representation should be benchmarked before using very large concrete
event corpora.

## Benchmark

A reproducible benchmark is provided without CI thresholds:

```shell
PYTHONPATH=src python benchmarks/assessment_scaling.py --scenario wide
PYTHONPATH=src python benchmarks/assessment_scaling.py --scenario deep
PYTHONPATH=src python benchmarks/assessment_scaling.py --scenario group
```

The script varies logical rule count and event-domain size independently and
reports build, assessment, classification, and report-construction time. The
`group` scenario also exercises one logical rule with many runtime
occurrences.

Performance thresholds are intentionally not enforced in CI yet. The benchmark
is an engineering instrument while the experimental API and workloads are
still being established.

## Current limitations

This branch deliberately does not add:

- a compiler from arbitrary Wazuh conditions or regexes to finite-domain
  predicates;
- SQLite or DuckDB persistence;
- Flask/UI integration;
- claims of complete Wazuh runtime emulation.

Those concerns can consume the stable `AssessmentReport` boundary later
without changing the evaluation algorithms.

The exactness claim is limited to evaluation over the supplied finite universe
using the structural Wazuh semantics modeled by this subsystem.
