from __future__ import annotations

from typing import Any, Final, Iterable

from networkx import MultiDiGraph

ATOMIC_RELATION_TYPES: Final[frozenset[str]] = frozenset({
    "root",
    "if_sid",
    "if_group",
})
TEMPORAL_RELATION_TYPES: Final[frozenset[str]] = frozenset({
    *ATOMIC_RELATION_TYPES,
    "if_matched_sid",
    "if_matched_group",
})
TEMPORAL_EDGE_TYPES: Final[frozenset[str]] = frozenset({
    "if_matched_sid",
    "if_matched_group",
})


def _parent_edges(
    graph: MultiDiGraph,
    node_id: str,
    allowed_relations: Iterable[str],
) -> list[dict[str, Any]]:
    allowed = set(allowed_relations)
    edges: list[dict[str, Any]] = []

    for parent_id, _, key, data in graph.in_edges(
        node_id, keys=True, data=True
    ):
        relation_type = data.get("relation_type", "unknown")
        if relation_type not in allowed:
            continue

        edge = {
            "source": parent_id,
            "target": node_id,
            "relation_type": relation_type,
            "edge_key": key,
        }
        if data.get("selector") is not None:
            edge["selector"] = data["selector"]
        edges.append(edge)

    edges.sort(
        key=lambda edge: (
            str(edge["source"]),
            str(edge["relation_type"]),
            str(edge["edge_key"]),
        )
    )
    return edges


def enumerate_paths(
    graph: MultiDiGraph,
    target_id: str,
    allowed_relations: Iterable[str] = ATOMIC_RELATION_TYPES,
    root_id: str = "0",
) -> list[dict[str, Any]]:
    """Return every simple root-to-target path using allowed edge types."""
    if target_id not in graph or root_id not in graph:
        return []

    paths: list[dict[str, Any]] = []

    def walk(
        node_id: str,
        reverse_nodes: list[str],
        reverse_edges: list[dict[str, Any]],
        visited: set[str],
    ) -> None:
        if node_id == root_id:
            paths.append({
                "nodes": list(reversed(reverse_nodes)),
                "edges": list(reversed(reverse_edges)),
            })
            return

        for edge in _parent_edges(
            graph, node_id, allowed_relations
        ):
            parent_id = str(edge["source"])
            if parent_id in visited:
                continue

            walk(
                parent_id,
                reverse_nodes + [parent_id],
                reverse_edges + [edge],
                visited | {parent_id},
            )

    walk(target_id, [target_id], [], {target_id})
    return paths


def flatten_atomic_conditions(
    graph: MultiDiGraph,
    path: dict[str, Any],
) -> list[dict[str, Any]]:
    """Flatten local atomic conditions in root-to-target order."""
    nodes = path.get("nodes", [])
    if not nodes:
        return []

    target_id = str(nodes[-1])
    rows: list[dict[str, Any]] = []

    for node_id in nodes:
        if node_id == "0" or node_id not in graph:
            continue

        for condition in graph.nodes[node_id].get("conditions", []):
            row = {
                "origin_rule_id": str(node_id),
                "inherited": str(node_id) != target_id,
                "tag": condition.get("tag"),
                "value": condition.get("value", ""),
            }
            if condition.get("kind") is not None:
                row["kind"] = condition["kind"]
            if condition.get("attributes"):
                row["attributes"] = dict(condition["attributes"])
            rows.append(row)

    return rows


def resolve_atomic_paths(
    graph: MultiDiGraph,
    target_id: str,
) -> list[dict[str, Any]]:
    """Enumerate atomic paths and attach their flattened conditions."""
    paths = enumerate_paths(graph, target_id)
    for path in paths:
        conditions = flatten_atomic_conditions(graph, path)
        path["conditions"] = conditions
        path["condition_count"] = len(conditions)
    return paths


def flatten_temporal_conditions(
    graph: MultiDiGraph,
    path: dict[str, Any],
) -> list[dict[str, Any]]:
    """Flatten a temporal path while retaining condition scope."""
    nodes = path.get("nodes", [])
    edges = path.get("edges", [])
    if not nodes:
        return []

    target_id = str(nodes[-1])
    rows: list[dict[str, Any]] = []

    for index, node_id in enumerate(nodes):
        if node_id == "0" or node_id not in graph:
            continue

        downstream_edges = edges[index:]
        ancestor_scope = (
            "historical_source"
            if any(
                edge.get("relation_type") in TEMPORAL_EDGE_TYPES
                for edge in downstream_edges
            )
            else "current_event"
        )

        for condition in graph.nodes[node_id].get("conditions", []):
            row = {
                "origin_rule_id": str(node_id),
                "scope": (
                    "current_event"
                    if str(node_id) == target_id
                    else ancestor_scope
                ),
                "inherited": str(node_id) != target_id,
                "tag": condition.get("tag"),
                "value": condition.get("value", ""),
            }
            if condition.get("kind") is not None:
                row["kind"] = condition["kind"]
            if condition.get("attributes"):
                row["attributes"] = dict(condition["attributes"])
            rows.append(row)

        if str(node_id) == target_id:
            for condition in graph.nodes[node_id].get(
                "temporal_conditions", []
            ):
                row = {
                    "origin_rule_id": str(node_id),
                    "scope": "temporal",
                    "inherited": False,
                    "tag": condition.get("tag"),
                    "value": condition.get("value", ""),
                }
                if condition.get("kind") is not None:
                    row["kind"] = condition["kind"]
                if condition.get("attributes"):
                    row["attributes"] = dict(condition["attributes"])
                rows.append(row)

    return rows


def resolve_temporal_paths(
    graph: MultiDiGraph,
    target_id: str,
) -> list[dict[str, Any]]:
    """Enumerate temporal paths and attach scoped flattened conditions."""
    paths = enumerate_paths(
        graph,
        target_id,
        allowed_relations=TEMPORAL_RELATION_TYPES,
    )
    for path in paths:
        conditions = flatten_temporal_conditions(graph, path)
        path["conditions"] = conditions
        path["condition_count"] = len(conditions)
    return paths
