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

These semantics are separate from the existing condition-path visualization.
For example, the UI graph still deliberately omits `if_level`, while the
source-faithful evaluator models it because runtime reconstruction requires it.

## Exact finite-domain evaluation

The assessor does not attempt arbitrary symbolic regex satisfiability.
Instead, the caller supplies a finite event universe and a bitset predicate for
each logical rule.

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

- `never_candidate`: the rule predicate has no events in the supplied domain.
- `unreachable`: the occurrence has candidate events, but no event reaches
  that point in its sibling list.
- `fully_shadowed`: events reach the sibling list, but all candidate events
  were consumed before this occurrence.
- `partially_shadowed`: some candidate events are consumed earlier while
  others still match.
- `dropped`: the occurrence consumes events through level-0 drop behavior.
- `never_selected`: the occurrence matches events but is never itself
  selected and is not classified as a level-0 drop. This includes `noalert`
  gates and regions fully consumed by descendants.

A finding carries a deterministic representative event, the occurrence path,
and the earlier blocking occurrence when one can be identified. The witness is
evidence for the finding; it is not a second evaluation algorithm.

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
