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
nodes introduced by missing dependency IDs. Modeled load issues are
available as `modeled_load_issues` on declared nodes.

This method is **not** invoked during ordinary XML graph generation.
It does not replace source edges, rewrite candidate snapshots, change
Flask graph presentation, or claim that Wazuh accepted any rule.
`accepted` here means *accepted by RuleVis's occurrence model*, not
confirmed by a running Wazuh manager. The configured manager include
order and runtime loader may differ from RuleVis's file scan. A model
occurrence-budget exception leaves the previously published projection
unchanged. The N2 issue requires version-pinned differential tests
before presenting this model as verified effective runtime attachment.

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
