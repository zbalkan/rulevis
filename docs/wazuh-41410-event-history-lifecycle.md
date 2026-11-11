# Wazuh 4.14.10 native event-history lifecycle validation

## Status

**Test plan only; no event-history runtime equivalence is claimed.** The merged
loader oracle validates initial RuleNode attachments and SID/group
registrations for pinned structural scenarios. It does not execute real
event-history insertion, search, expiry or cleanup. This branch introduces
a separate lifecycle test contract and no production UI changes.

## Upstream behavior to establish experimentally

| Behavior | Wazuh 4.14.10 source | Native observation required |
| --- | --- | --- |
| SID insertion before group insertion | `analysisd.c` 2233–2259 | Lists actually receiving a generated event when both are configured |
| Group-list multiplicity | `analysisd.c` 2245–2259 | Physical group-list append counts and pointer identity |
| SID search | `eventinfo.c` `Search_LastSids` | Selected events, frequency count and suppression |
| Group search | `eventinfo.c` `Search_LastGroups` | Selected events, frequency count and suppression |
| Timeframe boundary | `eventinfo.c` `Search_LastSids` / `Search_LastGroups` | Whether candidate events are considered expired |
| Agent partition | `eventinfo.c` | Same-agent comparison unless global-frequency is enabled |
| Matched-level interference | `eventinfo.c` | Rejection when historical event's matched level is at least the consumer level |
| Eviction and teardown | `eventinfo_list.c`, `eventinfo.c` `Free_Eventinfo` | History-list unlinking, alias handling and memory safety |

The `if (sid_prev_matched) ... else if (group_prev_matched)` branch in
`analysisd.c` is a specific high-value hypothesis: a logical source with
both subscriptions may populate only the SID list at runtime. It must be
confirmed through an instrumented native event and should not be promoted
from source inference to observed fact prematurely.

## Capture contract

The machine-readable plan is
`tests/fixtures/wazuh_41410_event_lifecycle.json`.
It contains test identifiers, ordered operations and observable fields,
but intentionally **does not include fabricated expected outcomes**.
The corresponding Python test checks coverage and schema; it is **not**
an event-history behavioral test.

The next implementation must isolate `wazuh-analysisd` with the same
pinned binary, disposable root and configuration provenance safeguards
used by the loader oracle. Add an independent injection mechanism and
inspect native `Eventinfo`, `OSList`, `RuleInfo` pointers and list
membership at stable breakpoints. Keep timestamps deterministic where
possible, capture both inputs and native observations, and mark any
unreached breakpoint or invalid pointer as an incomplete observation.

Do not reinterpret `wazuh-analysisd -t` or the loader-only GDB snapshot
as proof of historical-event delivery. Expiry, global frequency, cross-agent
isolation and memory cleanup require actual event execution. Avoid
unbounded waits and never execute these fixtures on a production manager.

## Acceptance criteria

The lifecycle phase can claim native validation only after every scenario
has independent evidence of event submission and post-operation state;
source and binary digests, exact scenario configuration and debugger
transcripts are retained; and expected behavior is derived and compared
without relying on modeled RuleVis predictions as the observation.
Any actual segmentation fault or invalid ownership is recorded as
a native failure, not normalized away.

This test plan deliberately leaves the existing declared graph, runtime
attachment projection and advisory UI unchanged.
