"""Potential Wazuh 4.14.10 correlation gaps visible in declared RuleVis graphs.

The graph contains declared references, not verified analysisd registrations.
Warnings are therefore diagnostic risk indicators, never proof that an
alert was dropped. The scan is O(V + E); sorting collected references adds O(K log K)
where K is the number of warning references.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx


def _ids_text(rule_ids: set[str]) -> str:
    values = sorted(rule_ids, key=_sort_id)
    shown = ", ".join(values[:5])
    return f"{shown} (+{len(values) - 5} more)" if len(values) > 5 else shown


def _modeled_rejected(attrs: dict[str, Any]) -> bool:
    """Use modeled rejection only when the optional projection was computed."""
    return attrs.get("modeled_acceptance") in {"rejected", "undeclared_reference"}


def _warning(code: str, message: str, *, phase: str,
             rule_ids: set[str], related_rule_ids: set[str] | None = None) -> dict[str, Any]:
    """Structured declared-graph evidence; never represent manager registration."""
    return {
        "code": code,
        "message": message,
        "basis": "declared",
        "phase": phase,
        "rule_ids": sorted(rule_ids, key=_sort_id),
        "related_rule_ids": sorted(related_rule_ids or (), key=_sort_id),
        "wazuh_version": "4.14.10",
        "upstream_issue": "https://github.com/wazuh/wazuh/issues/41279",
    }


def _sort_id(value: str) -> tuple[bool, int | str]:
    return (not value.isdigit(), int(value) if value.isdigit() else value)


def correlation_warnings(graph: nx.MultiDiGraph) -> dict[str, list[dict[str, Any]]]:
    """Identify declared group edges lost by scan order and dual-history risks.

    Only explicitly false load-order candidate edges constitute late sources.
    Dual-history checks require an earlier scanned SID source and an eligible
    group source. They still do not establish runtime acceptance.
    """
    late_targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    late_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    sid_subscribers: dict[str, set[str]] = defaultdict(set)
    group_subscribers: dict[str, set[str]] = defaultdict(set)
    load_index = {
        rule_id: index for index, (rule_id, attrs) in enumerate(graph.nodes(data=True))
        if attrs.get("file")
    }

    for source, target, data in graph.edges(data=True):
        relation = data.get("relation_type")
        target_data = graph.nodes[target]
        if data.get("shadowed_by"):
            continue
        if relation == "if_group":
            precedence = target_data.get("selector_precedence") or {}
            if precedence.get("effective", "if_group") != "if_group":
                continue
        elif relation == "if_matched_group":
            if target_data.get("historical_search", "if_matched_group") != "if_matched_group":
                continue

        if relation in {"if_group", "if_matched_group"} and data.get("load_order_candidate") is False:
            late_targets[(target, relation)].add(source)
            late_sources[(source, relation)].add(target)

        if relation == "if_matched_sid":
            # A rejected consumer never reaches OS_MarkID. A selector
            # shadowed by group lookup is likewise not SID history.
            if _modeled_rejected(target_data):
                continue
            if target_data.get("historical_search", "if_matched_sid") != "if_matched_sid":
                continue
            if source in load_index and target in load_index and load_index[source] < load_index[target]:
                sid_subscribers[source].add(target)
        elif relation == "if_matched_group" and data.get("load_order_candidate") is True:
            if not _modeled_rejected(target_data):
                group_subscribers[source].add(target)

    warnings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (target, relation), sources in sorted(late_targets.items()):
        kind = "GROUP_LOAD_ORDER" if relation == "if_group" else "TEMPORAL_GROUP_LOAD_ORDER"
        label = "structural attachment" if relation == "if_group" else "historical registration"
        warnings[target].append(_warning(kind, (

                f"Source rule(s) {_ids_text(sources)} occur after this rule in the scanned XML order. "
                f"Wazuh 4.14.10 does not revisit earlier {label} for new group sources. "
                "These declared edges may not exist at runtime."
            ), phase="structural_attachment" if relation == "if_group" else "historical_registration",
            rule_ids=sources))

    for (source, relation), targets in sorted(late_sources.items()):
        kind = "GROUP_LOAD_ORDER" if relation == "if_group" else "TEMPORAL_GROUP_LOAD_ORDER"
        label = "structural" if relation == "if_group" else "historical"
        warnings[source].append(_warning(kind, (

                f"This rule occurs after group-dependent rule(s) {_ids_text(targets)} in the scanned XML order. "
                f"Their {label} relationship may not include it in Wazuh 4.14.10."
            ), phase="structural_attachment" if relation == "if_group" else "historical_registration",
            rule_ids=targets))

    for source in sorted(sid_subscribers.keys() & group_subscribers.keys()):
        sid_targets = sid_subscribers[source]
        group_targets = group_subscribers[source]
        warnings[source].append(_warning("DUAL_HISTORY", (

                f"Potential simultaneous SID-history subscribers ({_ids_text(sid_targets)}) and "
                f"group-history subscribers ({_ids_text(group_targets)}). Wazuh 4.14.10 "
                "records only SID history when both lists are active; group events may be lost."
            ), phase="history_insertion", rule_ids=group_targets, related_rule_ids=sid_targets))
        for target in sorted(group_targets):
            warnings[target].append(_warning("DUAL_HISTORY", (

                    f"Source rule {source} also has SID-history subscribers. In Wazuh 4.14.10, "
                    "SID-history recording takes precedence and may suppress this group history."
                ), phase="history_insertion", rule_ids={source}, related_rule_ids=sid_targets))

    return dict(warnings)
