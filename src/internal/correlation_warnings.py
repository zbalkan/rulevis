"""Advisory warnings for Wazuh 4.14.10 group-correlation limitations.

Declared RuleVis relationships and scan order do not prove actual analysisd
registrations. Model acceptance, when supplied, qualifies the evidence but
does not change its declared-only basis. Scanning is O(V + E), with an
additional O(K log K) bound for sorted warning references.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx

REJECTED = frozenset({"rejected", "undeclared_reference"})


def _sort_id(value: str) -> tuple[bool, int | str]:
    return (not value.isdigit(), int(value) if value.isdigit() else value)


def _ordered(rule_ids: set[str]) -> list[str]:
    return sorted(rule_ids, key=_sort_id)


def _ids_text(rule_ids: set[str]) -> str:
    values = _ordered(rule_ids)
    shown = ", ".join(values[:5])
    return f"{shown} (+{len(values) - 5} more)" if len(values) > 5 else shown


def _modeled_rejected(attrs: dict[str, Any]) -> bool:
    """The optional projection can explicitly reject a declaration."""
    return attrs.get("modeled_acceptance") in REJECTED


def _dependency_acceptance(
    graph: nx.MultiDiGraph, dependents: set[str],
) -> tuple[dict[str, str], str]:
    """Distinguish rejected dependencies without asserting runtime attachment."""
    modeled = {
        rule_id: graph.nodes[rule_id]["modeled_acceptance"]
        for rule_id in _ordered(dependents)
        if graph.nodes[rule_id].get("modeled_acceptance") is not None
    }
    status = (
        "inactive_declaration"
        if dependents and all(modeled.get(rule_id) in REJECTED for rule_id in dependents)
        else "unverified"
    )
    return modeled, status


def _warning(
    code: str, message: str, *, phase: str, affected_rule_id: str,
    source_rule_ids: set[str], dependent_rule_ids: set[str] | None = None,
    sid_subscriber_rule_ids: set[str] | None = None,
    group_subscriber_rule_ids: set[str] | None = None,
    dependent_modeled_acceptance: dict[str, str] | None = None,
    relationship_status: str = "unverified",
) -> dict[str, Any]:
    """Structured, role-stable declared evidence for API and UI consumers."""
    return {
        "code": code,
        "message": message,
        "basis": "declared",
        "phase": phase,
        "affected_rule_id": affected_rule_id,
        "source_rule_ids": _ordered(source_rule_ids),
        "dependent_rule_ids": _ordered(dependent_rule_ids or set()),
        "sid_subscriber_rule_ids": _ordered(sid_subscriber_rule_ids or set()),
        "group_subscriber_rule_ids": _ordered(group_subscriber_rule_ids or set()),
        "dependent_modeled_acceptance": dependent_modeled_acceptance or {},
        "relationship_status": relationship_status,
        "wazuh_version": "4.14.10",
        "upstream_issue": "https://github.com/wazuh/wazuh/issues/41279",
    }


def correlation_warnings(graph: nx.MultiDiGraph) -> dict[str, list[dict[str, Any]]]:
    """Identify potential late group sources and dual-history overlaps.

    Only explicitly false load-order candidate edges are late sources.
    The dual-history check is based on declared relationships, excluding
    historical consumers/sources rejected by an optional modeled projection.
    No result establishes actual analysisd event delivery or alert loss.
    """
    late_targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    late_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    sid_subscribers: dict[str, set[str]] = defaultdict(set)
    group_subscribers: dict[str, set[str]] = defaultdict(set)
    load_index = {
        rule_id: index
        for index, (rule_id, attrs) in enumerate(graph.nodes(data=True))
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
        phase = "structural_attachment" if relation == "if_group" else "historical_registration"
        label = "structural attachment" if relation == "if_group" else "historical registration"
        modeled, status = _dependency_acceptance(graph, {target})
        qualifier = (
            " This dependent declaration was rejected by RuleVis's optional loader model; "
            "the declared edge does not represent an active runtime relationship."
            if status == "inactive_declaration" else
            " These declared edges may not exist at runtime."
        )
        warnings[target].append(_warning(
            kind,
            f"Source rule(s) {_ids_text(sources)} occur after this rule in the scanned XML order. "
            f"Wazuh 4.14.10 does not revisit earlier {label} for new group sources."
            + qualifier,
            phase=phase, affected_rule_id=target, source_rule_ids=sources,
            dependent_rule_ids={target}, dependent_modeled_acceptance=modeled,
            relationship_status=status,
        ))

    for (source, relation), targets in sorted(late_sources.items()):
        kind = "GROUP_LOAD_ORDER" if relation == "if_group" else "TEMPORAL_GROUP_LOAD_ORDER"
        phase = "structural_attachment" if relation == "if_group" else "historical_registration"
        label = "structural" if relation == "if_group" else "historical"
        modeled, status = _dependency_acceptance(graph, targets)
        qualifier = (
            " All referenced dependents were rejected by RuleVis's optional loader model."
            if status == "inactive_declaration" else ""
        )
        warnings[source].append(_warning(
            kind,
            f"This rule occurs after group-dependent rule(s) {_ids_text(targets)} in the scanned XML order. "
            f"Their {label} relationship may not include it in Wazuh 4.14.10."
            + qualifier,
            phase=phase, affected_rule_id=source, source_rule_ids={source},
            dependent_rule_ids=targets, dependent_modeled_acceptance=modeled,
            relationship_status=status,
        ))

    for source in sorted(sid_subscribers.keys() & group_subscribers.keys(), key=_sort_id):
        if _modeled_rejected(graph.nodes[source]):
            continue
        sid_targets = sid_subscribers[source]
        group_targets = group_subscribers[source]
        message = (
            f"Potential simultaneous SID-history subscribers ({_ids_text(sid_targets)}) and "
            f"group-history subscribers ({_ids_text(group_targets)}). Wazuh 4.14.10 "
            "records only SID history when both lists are active; group events may be lost."
        )
        warnings[source].append(_warning(
            "DUAL_HISTORY", message,
            phase="history_insertion", affected_rule_id=source,
            source_rule_ids={source}, dependent_rule_ids=group_targets,
            sid_subscriber_rule_ids=sid_targets,
            group_subscriber_rule_ids=group_targets,
        ))
        for target in _ordered(group_targets):
            warnings[target].append(_warning(
                "DUAL_HISTORY",
                f"Source rule {source} also has SID-history subscribers. In Wazuh 4.14.10, "
                "SID-history recording takes precedence and may suppress this group history.",
                phase="history_insertion", affected_rule_id=target,
                source_rule_ids={source}, dependent_rule_ids={target},
                sid_subscriber_rule_ids=sid_targets,
                group_subscriber_rule_ids=group_targets,
            ))

    return dict(warnings)
