from __future__ import annotations

import json
import os
import pickle
import sys
from typing import Any, Union

from flask import Flask, jsonify, render_template_string, request
from flask.wrappers import Response
from networkx import MultiDiGraph

from internal.conditions import (
    resolve_atomic_paths,
    resolve_temporal_paths,
)
from internal.correlation_warnings import correlation_warnings

PRECOMPUTED_BLOCK_SIZES: list[int] = [1, 10, 50, 100, 250, 500]
PRECOMPUTED_HEATMAPS: dict[int, Any] = {}


def parse_start(idstr: str) -> int:
    if not idstr:
        return 0
    s = str(idstr).strip()
    for sep in ("-", "–"):
        if sep in s:
            s = s.split(sep, 1)[0]
            break
    try:
        return int(s)
    except Exception:
        return 0


def precompute_heatmaps(base_blocks: list[dict[str, Any]]) -> None:
    # Use both start and count!
    starts_and_counts = [(parse_start(b.get("id")), int(  # type: ignore
        b.get("count", 0))) for b in base_blocks]
    max_start = max((start for start, _ in starts_and_counts), default=0)
    for bs in PRECOMPUTED_BLOCK_SIZES:
        if bs == 1:
            ids = sorted(str(start) for start, _ in starts_and_counts)
            PRECOMPUTED_HEATMAPS[bs] = {
                "block_size": 1,
                "ids": ids
            }
        else:
            acc: dict[str, Any] = {}
            for start, count in starts_and_counts:
                bucket = (start // bs) * bs
                key = f"{bucket}-{bucket + bs - 1}"
                acc[key] = acc.get(key, 0) + count  # Use the original count!
            blocks = [{"id": k, "count": v} for k, v in acc.items()]
            blocks.sort(key=lambda block: int(block["id"].split("-")[0]))
            PRECOMPUTED_HEATMAPS[bs] = {
                "metadata": {"block_size": bs, "max_id": max_start, "total_blocks": len(blocks)},
                "blocks": blocks
            }


def create_app(graph_path: str, stats_path: str, heatmap_path: str) -> Flask:
    if not os.path.isfile(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    if not os.path.isfile(stats_path):
        raise FileNotFoundError(f"Stats file not found: {stats_path}")

    with open(graph_path, "rb") as bf:
        G: MultiDiGraph = pickle.load(bf)

    with open(stats_path, "r", encoding='utf-8') as f:
        try:
            # Validate that the stats file is valid JSON
            STATS_DATA = json.load(f)
            # Simple validation to ensure keys exist
            required_keys = [
                "cycles", "top_direct_descendants", "top_indirect_descendants",
                "top_direct_ancestors", "top_indirect_ancestors", "isolated_rules"
            ]
            if not all(key in STATS_DATA for key in required_keys):
                raise ValueError("Stats file is missing required keys.")
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(f"Stats file '{stats_path}' is corrupted or invalid: {e}")

    if not os.path.isfile(heatmap_path):
        raise FileNotFoundError(f"Heatmap file not found: {heatmap_path}")

    with open(heatmap_path, "r") as f:
        try:
            HEATMAP_DATA = json.load(f)
        except json.JSONDecodeError:
            raise RuntimeError(f"Heatmap file '{heatmap_path}' is corrupted.")

    # Precompute heatmaps for all sizes on app startup
    base_blocks = HEATMAP_DATA.get("blocks", [])
    precompute_heatmaps(base_blocks)
    CORRELATION_WARNINGS = correlation_warnings(G)
    show_correlation_notice = any(
        data.get('relation_type') in {'if_group', 'if_matched_group'}
        for _, _, data in G.edges(data=True)
    ) or any(
        attrs.get('historical_search') == 'if_matched_group'
        or (attrs.get('selector_precedence') or {}).get('effective') == 'if_group'
        for _, attrs in G.nodes(data=True)
    )

    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None  # type: ignore
    app = Flask(__name__)

    # ---------- shared helpers ----------
    def structural_children(nid: str) -> list[str]:
        """Expand only visible structural dependencies, not level candidates."""
        return [
            child for child in G.successors(nid)
            if any(
                data.get("relation_type") != "if_level"
                for data in G.get_edge_data(nid, child, default={}).values()
            )
        ]

    def serialize_node(nid: str, displayed: set[str] | None = None) -> dict[str, Any]:
        attrs = G.nodes[nid]
        children = structural_children(nid)
        payload = {
            "id": nid,
            "correlation_warning_count": len(CORRELATION_WARNINGS.get(nid, ())),
            **{
                key: value for key, value in attrs.items()
                if key not in {"expandable", "children_ids"}
                and not key.startswith("_")
            },
            "children_ids": children,
        }
        if displayed is not None:
            payload["expandable"] = any(child not in displayed for child in children)
        return payload

    def rejected_reason(rule_id: str) -> str | None:
        precedence = G.nodes[rule_id].get("selector_precedence") or {}
        if precedence.get("rejected"):
            return precedence.get("rejection_reason") or precedence.get("invalid")
        return None

    def shadowed_by(rule_id: str, relation: str) -> str | None:
        precedence = G.nodes[rule_id].get("selector_precedence") or {}
        if relation in precedence.get("shadowed", ()):
            return precedence.get("effective")
        return None

    def edge_shadowed_by(rule_id: str, edge_data: dict) -> str | None:
        # Structural precedence is node-wide; historical-search precedence
        # applies to the individual declared temporal edge.
        return edge_data.get("shadowed_by") or shadowed_by(
            rule_id, edge_data.get("relation_type", "unknown")
        )

    def level_parent_summary(rule_id: str) -> dict[str, int]:
        declared = 0
        candidates = 0
        for _, _, _, data in G.in_edges(rule_id, keys=True, data=True):
            if data.get("relation_type") != "if_level":
                continue
            declared += 1
            if data.get("load_order_candidate") is True:
                candidates += 1
        return {"declared": declared, "load_order_candidates": candidates}

    def structural_edges(u: str, v: str) -> list[dict[str, Any]]:
        """Keep parallel non-threshold edges in the force-directed graph."""
        return [
            {
                "source": u,
                "target": v,
                "relation_type": data.get("relation_type", "unknown"),
                **(
                    {"rejected_reason": rejected_reason(v)}
                    if rejected_reason(v) else {}
                ),
                **(
                    {"shadowed_by": edge_shadowed_by(v, data)}
                    if edge_shadowed_by(v, data) else {}
                ),
            }
            for data in G.get_edge_data(u, v, default={}).values()
            if data.get("relation_type") != "if_level"
        ]

    def error(message: str, code: int = 400) -> tuple[Response, int]:
        return jsonify({"error": message}), code

    def _handle_root(displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        root = "0"
        if root not in G:
            return error("Root node not found", 404)
        children = list(G.successors(root))
        nodes = [serialize_node(root, displayed)] + [serialize_node(c, displayed) for c in children]
        edges = [
            {
                "source": root,
                "target": child,
                "relation_type": "no_parent",
                **(
                    {"rejected_reason": rejected_reason(child)}
                    if rejected_reason(child) else {}
                ),
            }
            for child in children
        ]
        return jsonify({"nodes": nodes, "edges": edges})

    def _handle_batch(ids_param: str, displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        node_ids = [nid for nid in ids_param.split(",") if nid]
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})
        nodes = [serialize_node(nid, displayed) for nid in node_ids if nid in G]
        all_relevant = set(node_ids) | displayed
        sub_edges = [
            edge
            for u, v in dict.fromkeys(G.subgraph(all_relevant).edges())
            if u in node_ids or v in node_ids
            for edge in structural_edges(u, v)
        ]
        return jsonify({"nodes": nodes, "edges": sub_edges})

    def _handle_search(node_id: str, displayed: set[str]) -> Union[Response, tuple[Response, int]]:
        if node_id not in G:
            return error(f"Node '{node_id}' not found", 404)

        node_obj = serialize_node(node_id, displayed)
        edges = []
        for p in G.predecessors(node_id):
            if p in displayed:
                edges.extend(structural_edges(p, node_id))
        for c in G.successors(node_id):
            if c in displayed:
                edges.extend(structural_edges(node_id, c))
        return jsonify({"nodes": [node_obj], "edges": edges})

    def _handle_single_node(node_id: str, neighbor_mode: str,
                            include_details: bool, displayed: set[str]) -> Union[Response, tuple[Response, int]]:

        if node_id not in G:
            return error(f"Node '{node_id}' not found", 404)

        if include_details:
            node_data = G.nodes[node_id]
            parents = [
                {
                    "id": parent_id,
                    "relation_type": edge_data.get(
                        "relation_type", "unknown"
                    ),
                    "selector": edge_data.get("selector"),
                    **(
                        {"rejected_reason": rejected_reason(node_id)}
                        if rejected_reason(node_id) else {}
                    ),
                    **(
                        {"shadowed_by": edge_shadowed_by(node_id, edge_data)}
                        if edge_shadowed_by(node_id, edge_data)
                        else {}
                    ),
                    **(
                        {"load_order_candidate": edge_data["load_order_candidate"]}
                        if "load_order_candidate" in edge_data else {}
                    ),
                    **(
                        {"synthesized_from": edge_data["synthesized_from"]}
                        if "synthesized_from" in edge_data else {}
                    ),
                }
                for parent_id, _, _, edge_data in G.in_edges(
                    node_id, keys=True, data=True
                )
                if edge_data.get("relation_type") != "if_level"
            ]
            children = [
                {
                    "id": child_id,
                    "relation_type": edge_data.get(
                        "relation_type", "unknown"
                    ),
                    "selector": edge_data.get("selector"),
                    **(
                        {"rejected_reason": rejected_reason(child_id)}
                        if rejected_reason(child_id) else {}
                    ),
                    **(
                        {"shadowed_by": edge_shadowed_by(child_id, edge_data)}
                        if edge_shadowed_by(child_id, edge_data)
                        else {}
                    ),
                    **(
                        {"load_order_candidate": edge_data["load_order_candidate"]}
                        if "load_order_candidate" in edge_data else {}
                    ),
                    **(
                        {"synthesized_from": edge_data["synthesized_from"]}
                        if "synthesized_from" in edge_data else {}
                    ),
                }
                for _, child_id, _, edge_data in G.out_edges(
                    node_id, keys=True, data=True
                )
                if edge_data.get("relation_type") != "if_level"
            ]
            return jsonify({
                "id": node_id,
                "description": node_data.get("description"),
                "groups": node_data.get("groups", []),
                "mitre": node_data.get("mitre", []),
                "level": node_data.get("level"),
                "if_level": node_data.get("if_level"),
                "level_parents": level_parent_summary(node_id),
                "selector_precedence": node_data.get("selector_precedence"),
                "historical_search": node_data.get("historical_search"),
                "correlation_warnings": CORRELATION_WARNINGS.get(node_id, []),
                "file": node_data.get("file"),
                "temporal": bool(node_data.get("temporal", False)),
                "parents": parents,
                "children": children
            })

        nodes = [serialize_node(node_id, displayed)]
        edges = []
        if neighbor_mode in {"parents", "both"}:
            for p in G.predecessors(node_id):
                relationships = structural_edges(p, node_id)
                if not relationships:
                    continue
                nodes.append(serialize_node(p, displayed))
                edges.extend(relationships)
        if neighbor_mode in {"children", "both"}:
            for c in structural_children(node_id):
                nodes.append(serialize_node(c, displayed))
                edges.extend(structural_edges(node_id, c))
        return jsonify({"nodes": nodes, "edges": edges})

    # ---------- UI ----------
    @app.route("/")
    def index() -> str:
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Rule Graph Explorer</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <script src="https://d3js.org/d3.v7.min.js"></script>
            <link rel="stylesheet" href="static/styles.css">
        </head>
        <body>
        <div class="navbar">
            <div class="navbar-left">
                <div class="navbar-title">Interactive Rule Graph Explorer</div>
            </div>
            <div class="navbar-links">
                <button id="showHeatmapBtn">Show Heatmap</button>
                <button id="showStatsBtn">Show Stats</button>
                <button id="resetZoom">Reset Zoom</button>
                <button id="resetGraph">Reset Graph</button>
                <button id="toggleFocusBtn">Toggle focus off</button>
                <input type="text" id="searchBox" placeholder="Search Rule ID">
                <button id="searchBtn">Search</button>
            </div>
        </div>

        {% if show_correlation_notice %}
        <aside id="correlationNotice" {% if not warning_count %}class="correlation-notice-info"{% endif %} role="note" aria-label="Wazuh correlation limitations">
            <strong>Known Wazuh 4.14.10 group-correlation limitations.</strong>
            {% if warning_count %}
            {{ warning_count }} rule(s) have potential correlation gaps in the scanned graph.
            Select a marked rule to review its warning.
            {% else %}
            No specific scan-order risk was identified; this is not proof of runtime correctness.
            {% endif %}
            <a href="https://github.com/wazuh/wazuh/issues/41279"
               target="_blank" rel="noopener noreferrer">Upstream issue #41279</a>
            <span>Findings are based on scanned XML, not verified manager behavior.</span>
        </aside>
        {% endif %}

        <div class="content">
            <canvas></canvas>
        </div>

        <div id="detailsPanel" class="side-panel">
            <button id="detailsCloseBtn" class="panel-close-btn">×</button>
            <div id="detailsContent" class="panel-content">
                <p>Click on a node to see its details.</p>
            </div>
        </div>

        <div id="statsPanel" class="side-panel">
            <button id="statsCloseBtn" class="panel-close-btn">×</button>
            <div id="statsContent" class="panel-content">
                <p>Statistics loading...</p>
            </div>
        </div>

        <div id="heatmapModal" class="modal-overlay">
            <div id="heatmapContent">
            </div>
        </div>

        <div id="conditionsModal" class="modal-overlay">
            <div id="conditionsContent">
                <div class="conditions-modal-header">
                    <h2 id="conditionsTitle">Conditions</h2>
                    <button id="conditionsCloseBtn" class="modal-close-btn"
                            aria-label="Close conditions">×</button>
                </div>
                <p class="conditions-scope-note">
                    Resolved paths follow declared rule dependencies, including
                    <code>if_level</code>. They are source-level possibilities, not
                    verified analysisd runtime attachments.
                </p>
                <div id="conditionsBody"></div>
            </div>
        </div>

        <div class="footer">
            <p>Visit official Wazuh documentation for
               <a href="https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html" target="_blank">
               Wazuh Rule Syntax</a>.
            </p>
            <p>&copy; 2025 <a href="https://zaferbalkan.com" target="_blank">Zafer Balkan</a></p>
            <p>The brand <a href="https://wazuh.com/" target="_blank">Wazuh</a> and related marks,
               emblems and images are registered trademarks of their respective owners.
            </p>
        </div>

        <script src="static/tutorial.js" defer></script>
        <script src="static/graph.js" defer></script>
        </body>
        </html>
""", show_correlation_notice=show_correlation_notice,
                                 warning_count=len(CORRELATION_WARNINGS))

    # ---------- Consolidated APIs ----------
    @app.route("/api/nodes", methods=["GET"])
    def nodes() -> Union[Response, tuple[Response, int]]:
        """
        Dispatches requests to the appropriate handler based on query params.
        """
        mode = request.args.get("mode", "").strip().lower()
        node_id = request.args.get("id", "").strip()
        ids_param = request.args.get("ids", "").strip()
        neighbor_mode = request.args.get("neighbors", "").strip().lower() or ("children" if node_id else "none")
        include_details = request.args.get("include", "").strip().lower() == "details"
        displayed: set[str] = set(filter(None, request.args.get("displayed", "").split(",")))

        if mode == "root":
            return _handle_root(displayed)

        if ids_param:
            return _handle_batch(ids_param, displayed)

        if mode == "search":
            if not node_id:
                return error("mode=search requires an 'id' parameter", 400)
            return _handle_search(node_id, displayed)

        if node_id:
            return _handle_single_node(node_id, neighbor_mode, include_details, displayed)

        return error("Specify one of: mode=root | mode=search&id=... | id=... | ids=...", 400)

    @app.route("/api/edges", methods=["POST"])
    def edges() -> Response:
        """
        Unifies: /api/connections
        Body: { "ids": ["a","b","c"] }
        Returns all edges among provided ids.
        """
        payload = request.get_json(silent=True) or {}
        node_ids = payload.get("ids", [])
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})
        edges_list = [
            edge
            for u, v in dict.fromkeys(G.subgraph(node_ids).edges())
            for edge in structural_edges(u, v)
        ]
        return jsonify({"nodes": [], "edges": edges_list})

    @app.route("/api/level-parents", methods=["GET"])
    def level_parents() -> Union[Response, tuple[Response, int]]:
        """Return only visible candidates; never add them to graph physics."""
        node_id = request.args.get("id", "").strip()
        if node_id not in G:
            return error("Rule not found", 404)
        selector = G.nodes[node_id].get("if_level")
        if selector is None or str(selector) == "":
            return error("Rule has no if_level declaration", 400)
        raw = str(selector)
        if not raw.isascii() or not raw.isdigit() or not raw.lstrip("0"):
            return error("Rule has no valid positive if_level threshold", 400)
        precedence = G.nodes[node_id].get("selector_precedence") or {}
        if "if_level" in precedence.get("shadowed", ()):
            return error("if_level is shadowed by a higher-priority selector", 400)
        displayed = set(filter(None, request.args.get("displayed", "").split(",")))
        declared = 0
        load_order_candidates = 0
        visible = []
        for parent, _, _, data in G.in_edges(
            node_id, keys=True, data=True
        ):
            if data.get("relation_type") != "if_level":
                continue
            declared += 1
            if data.get("load_order_candidate") is True:
                load_order_candidates += 1
            if parent not in displayed or node_id not in displayed:
                continue
            visible.append({
                "source": parent,
                "target": node_id,
                "relation_type": "if_level",
                "selector": data.get("selector", str(selector)),
                "load_order_candidate": data.get("load_order_candidate"),
            })
        return jsonify({
            "selector": str(selector),
            "declared": declared,
            "load_order_candidates": load_order_candidates,
            "edges": visible,
        })

    @app.route("/api/conditions", methods=["GET"])
    def conditions() -> Union[Response, tuple[Response, int]]:
        node_id = request.args.get("id", "").strip()
        if not node_id:
            return error("An 'id' parameter is required", 400)
        if node_id not in G:
            return error(f"Node '{node_id}' not found", 404)
        if node_id == "0":
            return error("The synthetic root has no rule conditions", 400)

        node_data = G.nodes[node_id]
        clock_temporal = bool(node_data.get("temporal", False))
        has_temporal_conditions = bool(
            node_data.get("temporal_conditions", [])
        )
        condition_type = (
            "temporal" if has_temporal_conditions else "atomic"
        )
        paths = (
            resolve_temporal_paths(G, node_id)
            if has_temporal_conditions
            else resolve_atomic_paths(G, node_id)
        )

        return jsonify({
            "id": node_id,
            "condition_type": condition_type,
            "clock_temporal": clock_temporal,
            "paths": paths,
            "paths_truncated": bool(getattr(paths, "truncated", False)),
        })

    @app.route("/api/stats", methods=["GET"])
    def stats() -> Response:
        """Serves the pre-calculated graph statistics."""
        return jsonify(STATS_DATA)

    @app.route("/api/heatmap", methods=["GET"])
    def heatmap() -> Union[Response, tuple[Response, int]]:
        bs = request.args.get("block_size", type=int)
        if not bs or bs < 1:
            bs = 1

        if bs in PRECOMPUTED_HEATMAPS:
            return jsonify(PRECOMPUTED_HEATMAPS[bs])

        # Fallback for non-precomputed block sizes
        starts_and_counts = [(parse_start(b.get("id")), int(
            b.get("count", 0))) for b in base_blocks]
        if bs == 1:
            ids = sorted(str(start) for start, _ in starts_and_counts)
            return jsonify({"block_size": 1, "ids": ids})
        acc: dict[str, Any] = {}
        for start, count in starts_and_counts:
            bucket = (start // bs) * bs
            key = f"{bucket}-{bucket + bs - 1}"
            acc[key] = acc.get(key, 0) + count  # Use the original count!
        blocks = [{"id": k, "count": v} for k, v in acc.items()]
        blocks.sort(key=lambda block: int(block["id"].split("-")[0]))
        meta = {
            "block_size": bs,
            "max_id": max((start for start, _ in starts_and_counts), default=0),
            "total_blocks": len(blocks)
        }
        return jsonify({"metadata": meta, "blocks": blocks})

    return app
