import json
import os
import pickle
from typing import Any, Union

from flask import Flask, jsonify, render_template_string, request
from flask.wrappers import Response
from networkx import MultiDiGraph

def create_app(graph_path: str, stats_path: str, heatmap_path: str) -> Flask:
    if not os.path.isfile(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    if not os.path.isfile(stats_path):
        raise FileNotFoundError(f"Stats file not found: {stats_path}")

    with open(graph_path, "rb") as f:
        G: MultiDiGraph = pickle.load(f)

    with open(stats_path, "r") as f:
        try:
            # Validate that the stats file is valid JSON
            STATS_DATA = json.load(f)
            # Simple validation to ensure keys exist
            required_keys = [
                "top_direct_descendants", "top_indirect_descendants", 
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
    app = Flask(__name__)

    # ---------- shared helpers ----------
    def serialize_node(nid: str, displayed: set[str] | None = None) -> dict[str, Any]:
        attrs = G.nodes[nid]
        if displayed is None:
            # caller doesn't care about expandable computation
            return {"id": nid, **{k: v for k, v in attrs.items() if k != "expandable"}}
        expandable = any(child not in displayed for child in G.successors(nid))
        return {
            "id": nid,
            **{k: v for k, v in attrs.items() if k != "expandable"},
            "expandable": expandable,
        }

    def relation_type(u: str, v: str) -> str:
        data = G.get_edge_data(u, v)
        if not data:
            return "unknown"
        return next(iter(data.values()), {}).get("relation_type", "unknown")
    
    def make_edge(u: str, v: str) -> dict[str, Any]:
        return {"source": u, "target": v, "relation_type": relation_type(u, v)}

    def error(message: str, code: int = 400) -> tuple[Response, int]:
        return jsonify({"error": message}), code

    def _handle_root(displayed: set[str]) -> Union[Response, tuple[Response,int]]:
        root = "0"
        if root not in G:
            return error("Root node not found", 404)
        children = list(G.successors(root))
        nodes = [serialize_node(root, displayed)] + [serialize_node(c, displayed) for c in children]
        edges = [{"source": root, "target": c, "relation_type": "no_parent"} for c in children]
        return jsonify({"nodes": nodes, "edges": edges})

    def _handle_batch(ids_param: str, displayed: set[str]) -> Union[Response, tuple[Response,int]]:
        node_ids = [nid for nid in ids_param.split(",") if nid]
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})
        nodes = [serialize_node(nid, displayed) for nid in node_ids if nid in G]
        all_relevant = set(node_ids) | displayed
        sub_edges = [
            make_edge(u, v)
            for u, v in G.subgraph(all_relevant).edges()
            if u in node_ids or v in node_ids
        ]
        return jsonify({"nodes": nodes, "edges": sub_edges})

    def _handle_search(node_id: str, displayed: set[str]) -> Union[Response, tuple[Response,int]]:
        if node_id not in G:
            return error(f"Node '{node_id}' not found", 404)
        
        node_obj = serialize_node(node_id, displayed)
        edges = []
        for p in G.predecessors(node_id):
            if p in displayed:
                edges.append(make_edge(p, node_id))
        for c in G.successors(node_id):
            if c in displayed:
                edges.append(make_edge(node_id, c))
        return jsonify({"nodes": [node_obj], "edges": edges})

    def _handle_single_node(node_id: str, neighbor_mode: str, include_details: bool, displayed: set[str]) -> Union[Response, tuple[Response,int]]:
        if node_id not in G:
            return error(f"Node '{node_id}' not found", 404)

        if include_details:
            node_data = G.nodes[node_id]
            parents = [{"id": p, "relation_type": make_edge(p, node_id)["relation_type"]} for p in G.predecessors(node_id)]
            children = [{"id": c, "relation_type": make_edge(node_id, c)["relation_type"]} for c in G.successors(node_id)]
            return jsonify({
                "id": node_id,
                "description": node_data.get("description"),
                "groups": node_data.get("groups", []),
                "parents": parents,
                "children": children
            })

        nodes = [serialize_node(node_id, displayed)]
        edges = []
        if neighbor_mode in {"parents", "both"}:
            for p in G.predecessors(node_id):
                nodes.append(serialize_node(p, displayed))
                edges.append(make_edge(p, node_id))
        if neighbor_mode in {"children", "both"}:
            for c in G.successors(node_id):
                nodes.append(serialize_node(c, displayed))
                edges.append(make_edge(node_id, c))
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
                <input type="text" id="searchBox" placeholder="Search Rule ID">
                <button id="searchBtn">Search</button>
            </div>
        </div>

        <div class="content">
            <canvas></canvas>
        </div>

        <div id="detailsPanel" class="details-panel">
            <button id="detailsCloseBtn" class="details-close-btn">&times;</button>
            <div id="detailsContent" class="details-content">
                <p class="details-placeholder">Click on a node to see its details.</p>
            </div>
        </div>

        <div id="statsPanel" class="details-panel">
            <button id="statsCloseBtn" class="details-close-btn">&times;</button>
            <div id="statsContent" class="details-content">
                <p class="details-placeholder">Statistics loading...</p>
            </div>
        </div>

        <div id="heatmapModal" class="heatmap-modal">
            <div class="heatmap-container">
                <button id="heatmapCloseBtn" class="heatmap-close-btn">&times;</button>
                <div id="heatmapContent"></div>
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

        <script src="static/tutorial.js"></script>
        <script src="static/graph.js"></script>
        </body>
        </html>
""")

    # ---------- Consolidated APIs ----------
    @app.route("/api/nodes", methods=["GET"])
    def nodes() -> Union[Response, tuple[Response,int]]:
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
            if not node_id: return error("mode=search requires an 'id' parameter", 400)
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
        edges_list = [make_edge(u, v) for u, v in G.subgraph(node_ids).edges()]
        return jsonify({"nodes": [], "edges": edges_list})

    @app.route("/api/stats", methods=["GET"])
    def stats() -> Response:
        """Serves the pre-calculated graph statistics."""
        return jsonify(STATS_DATA)

    @app.route("/api/heatmap", methods=["GET"])
    def heatmap() -> Response:
        """Serves the pre-calculated heatmap data."""
        return jsonify(HEATMAP_DATA)
    
    return app
