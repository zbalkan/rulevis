from __future__ import annotations

from typing import Any, Final, Iterable

from networkx import MultiDiGraph

ATOMIC_RELATION_TYPES: Final[frozenset[str]] = frozenset({
    "root",
    "if_sid",
    "if_group",
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
