import os
import pickle
from typing import Any

from flask import Flask, jsonify, render_template_string, request
from flask.wrappers import Response
from networkx import MultiDiGraph

def create_app(graph_path: str) -> Flask:
    if not os.path.isfile(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    with open(graph_path, "rb") as f:
        G: MultiDiGraph = pickle.load(f)

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

    def neighbors_payload(nid: str, which: str) -> dict[str, list[dict[str, Any]]]:

        parents = (
            [{"id": p, "relation_type": relation_type(p, nid)} for p in G.predecessors(nid)]
            if which in ("parents", "both") else []
        )
        children = (
            [{"id": c, "relation_type": relation_type(nid, c)} for c in G.successors(nid)]
            if which in ("children", "both") else []
        )
        return {"parents": parents, "children": children}

    def relation_type(u: str, v: str) -> str:
        data = G.get_edge_data(u, v)
        if not data:
            return "unknown"
        return next(iter(data.values()), {}).get("relation_type", "unknown")
    
    def make_edge(u: str, v: str) -> dict[str, Any]:
        return {"source": u, "target": v, "relation_type": relation_type(u, v)}

    def error(message: str, code: int = 400) -> tuple[Response, int]:
        return jsonify({"error": message}), code

    # ---------- UI ----------
    @app.route("/")
    def index():
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
    def nodes():
        """
        Unifies: root, single node + neighbors, details, search, batch.
        Query params:
          mode: root | search (optional)
          id: target node id for single/search
          ids: comma-separated list for batch
          neighbors: none | parents | children | both (default=children when id given)
          include: details to include node metadata fields
          displayed: comma-separated ids used to compute 'expandable' and to filter search edges
        """
        mode = request.args.get("mode", "").strip().lower()
        node_id = request.args.get("id", "").strip()
        ids_param = request.args.get("ids", "").strip()
        neighbor_mode = request.args.get("neighbors", "").strip().lower() or ("children" if node_id else "none")
        include_details = request.args.get("include", "").strip().lower() == "details"
        displayed: set[str] = set(filter(None, request.args.get("displayed", "").split(",")))

        # Mode: root graph (root + its immediate children)
        if mode == "root":
            root = "0"
            if root not in G:
                return error("Root node not found", 404)
            children = list(G.successors(root))
            nodes = [serialize_node(root, displayed)] + [serialize_node(c, displayed) for c in children]
            edges = [{"source": root, "target": c, "relation_type": "no_parent"} for c in children]
            return jsonify({"nodes": nodes, "edges": edges})

        # Mode: batch fetch by ids (with optional displayed to compute expandables and edges)
        if ids_param:
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

        if node_id and node_id in G:
            node_obj = serialize_node(node_id, displayed)
        else:
            node_obj = None

        # Mode: search for a node id, return node plus edges only to displayed set
        if mode == "search":
            if not node_id or node_id not in G:
                return error(f"Node '{node_id}' not found", 404)

            edges = []
            for p in G.predecessors(node_id):
                if p in displayed:
                    edges.append(make_edge(p, node_id))
            for c in G.successors(node_id):
                if c in displayed:
                    edges.append(make_edge(node_id, c))
            return jsonify({"nodes": [node_obj], "edges": edges})

        # Mode: single node with optional neighbors and details
        if node_id:
            if node_id not in G:
                return error(f"Node '{node_id}' not found", 404)
            if include_details:
                node_data = G.nodes[node_id]
                neigh = neighbors_payload(node_id, "both")  # avoid name clash with neighbor_mode
                return jsonify({
                    "id": node_id,
                    "description": node_data.get("description"),
                    "groups": node_data.get("groups", []),
                    "parents": neigh["parents"],
                    "children": neigh["children"]
                })

            nodes = [node_obj]
            edges = []

            if neighbor_mode in {"parents", "children", "both"}:
                if neighbor_mode in {"parents", "both"}:
                    for p in G.predecessors(node_id):
                        nodes.append(serialize_node(p, displayed))
                        edges.append(make_edge(p, node_id))
                if neighbor_mode in {"children", "both"}:
                    for c in G.successors(node_id):
                        nodes.append(serialize_node(c, displayed))
                        edges.append(make_edge(node_id, c))

            return jsonify({"nodes": nodes, "edges": edges})

        # Default: nothing matched
        return error("Specify one of: mode=root | mode=search&id=..., or id=..., or ids=...", 400)

    @app.route("/api/edges", methods=["POST"])
    def edges():
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

    return app
