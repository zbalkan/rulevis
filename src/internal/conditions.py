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
RELATION_CONDITION_TAGS: Final[frozenset[str]] = frozenset({
    "if_sid",
    "if_group",
    "if_matched_sid",
    "if_matched_group",
})
PCRE2_META_CHARACTERS: Final[frozenset[str]] = frozenset(
    ".^$*+?{}[]()|"
)
OSREGEX_META_CHARACTERS: Final[frozenset[str]] = frozenset(
    "^$*+?{}[]()|\\<"
)
OSMATCH_META_CHARACTERS: Final[frozenset[str]] = frozenset(
    "^$|!\\"
)




def _parse_exact_literal_alternatives(
    value: Any,
    engine: str,
) -> frozenset[str] | None:
    """Parse exact alternatives without evaluating general regexes."""
    if not isinstance(value, str) or not value:
        return None

    parts: list[str] = []
    current: list[str] = []
    index = 0

    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value):
                return None
            current.extend((char, value[index + 1]))
            index += 2
            continue
        if char == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1

    parts.append("".join(current))
    literals: set[str] = set()

    for part in parts:
        if len(part) < 2 or not part.startswith("^") or not part.endswith("$"):
            return None

        body = part[1:-1]

        if engine in {"osregex", "osmatch"}:
            meta = (
                OSREGEX_META_CHARACTERS
                if engine == "osregex"
                else OSMATCH_META_CHARACTERS
            )
            if any(char in meta for char in body):
                return None
            literal = body.lower()
        elif engine == "pcre2":
            literal_chars: list[str] = []
            index = 0
            while index < len(body):
                char = body[index]
                if char == "\\":
                    if index + 1 >= len(body):
                        return None
                    escaped = body[index + 1]
                    if escaped.isalnum():
                        return None
                    literal_chars.append(escaped)
                    index += 2
                    continue
                if char in PCRE2_META_CHARACTERS:
                    return None
                literal_chars.append(char)
                index += 1
            literal = "".join(literal_chars)
        else:
            return None

        literals.add(literal)

    return frozenset(literals)

def _field_resolution_key(
    row: dict[str, Any],
) -> tuple[str | None, str, str] | None:
    if row.get("tag") != "field":
        return None

    attributes = row.get("attributes")
    if not isinstance(attributes, dict):
        return None

    name = attributes.get("name")
    if not isinstance(name, str) or not name:
        return None

    negate = str(attributes.get("negate", "")).lower()
    if negate in {"yes", "true", "1"}:
        return None

    engine = str(attributes.get("type", "osregex")).lower()
    if engine not in {"osregex", "osmatch", "pcre2"}:
        return None

    scope = row.get("scope")
    return (
        str(scope) if scope is not None else None,
        name,
        engine,
    )

def annotate_field_resolution(
    rows: list[dict[str, Any]],
) -> None:
    """Annotate provable same-field simplifications conservatively."""
    states: dict[
        tuple[str | None, str, str],
        dict[str, Any],
    ] = {}

    for row in rows:
        key = _field_resolution_key(row)
        if key is None:
            continue

        values = _parse_exact_literal_alternatives(
            row.get("value"),
            key[2],
        )
        if values is None:
            continue

        state = states.get(key)
        if state is None:
            states[key] = {
                "effective": values,
                "active": [row],
                "contradiction": False,
            }
            continue

        if state["contradiction"]:
            continue

        effective = state["effective"]
        intersection = effective & values

        if not intersection:
            row["resolution_status"] = "contradiction"
            row["resolution_note"] = (
                f"Contradicts prior constraints on {key[1]}"
            )
            state["contradiction"] = True
            continue

        if intersection == effective:
            row["resolution_status"] = "redundant"
            row["resolution_note"] = (
                f"Redundant after prior constraints on {key[1]}"
            )
            continue

        if intersection == values:
            for previous in state["active"]:
                previous["resolution_status"] = "subsumed"
                previous["resolution_note"] = (
                    "Subsumed by rule "
                    f"{row.get('origin_rule_id', '?')}"
                )
            state["effective"] = values
            state["active"] = [row]
            continue

        state["effective"] = intersection
        state["active"].append(row)


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
            if condition.get("tag") in RELATION_CONDITION_TAGS:
                continue

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
        annotate_field_resolution(conditions)
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
            if condition.get("tag") in RELATION_CONDITION_TAGS:
                continue

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

        for condition in graph.nodes[node_id].get(
            "temporal_conditions", []
        ):
            if condition.get("tag") in RELATION_CONDITION_TAGS:
                continue

            is_target = str(node_id) == target_id
            row = {
                "origin_rule_id": str(node_id),
                "scope": (
                    "temporal"
                    if is_target
                    else ancestor_scope
                ),
                "inherited": not is_target,
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
        annotate_field_resolution(conditions)
        path["conditions"] = conditions
        path["condition_count"] = len(conditions)
    return paths
