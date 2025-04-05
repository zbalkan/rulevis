import os
import pickle
from flask import Flask, jsonify, render_template_string
from networkx import MultiDiGraph


def create_app(graph_path: str) -> Flask:
    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found: {graph_path}")

    with open(graph_path, 'rb') as f:
        G: MultiDiGraph = pickle.load(f)

    app = Flask(__name__)

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
            <svg></svg>
            <div id="tooltip" class="tooltip"></div>
            <script src="static/main.js"></script>
        </div>

        <div class="footer">
            <p>Visit official Wazuh documentation for <a href="https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html" target="_blank">Wazuh Rule Syntax</a>.</p>
            <p>&copy; 2025 <a href="https://zaferbalkan.com" target="_blank">Zafer Balkan</a></p>
            <p>The brand <a href="https://wazuh.com/" target="_blank">Wazuh</a> and related marks, emblems and images are registered trademarks of their respective owners.</p>
        </div>
        </body>
        </html>
        """)

    @app.route("/api/root", methods=["GET"])
    def get_root_node():
        root = '0'
        if root not in G:
            return jsonify({"error": "Root node not found"}), 404

        children = list(G.successors(root))
        nodes = [
            {
                "id": nid,
                **{k: v for k, v in G.nodes[nid].items() if k != "node_type"},
                "has_children": (G.out_degree(nid) > 0),
                "is_expanded": (nid == root),
                "node_type": "default" if (nid == root or G.out_degree(nid) == 0) else "expandable"
            }
            for nid in [root] + children
        ]

        edges = [
            {
                "source": root,
                "target": child,
                "relation_type": "no_parent"
            }
            for child in children
        ]

        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/api/node/<node_id>", methods=["GET"])
    def get_node_children(node_id):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        children = list(G.successors(node_id))
        nodes = [
            {
                "id": nid,
                **{k: v for k, v in G.nodes[nid].items() if k != "node_type"},
                "has_children": (G.out_degree(nid) > 0),
                "node_type": "default" if (nid == node_id or G.out_degree(nid) == 0) else "expandable"
            }
            for nid in [node_id] + children
        ]
        edges = [
            {
                "source": node_id,
                "target": child,
                "relation_type": G.get_edge_data(node_id, child)[0].get("relation_type", "unknown")
            }
            for child in children
        ]

        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/api/parents/<node_id>", methods=["GET"])
    def get_node_parents(node_id):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        parents = list(G.predecessors(node_id))
        if not parents:
            parents = ["0"]

        nodes = [
            {
                "id": nid,
                **{k: v for k, v in G.nodes[nid].items() if k != "node_type"},
                "has_children": (G.out_degree(nid) > 0),
                "node_type": "default" if (nid == "0" or G.out_degree(nid) == 0) else "expandable"
            }
            for nid in parents + [node_id]
        ]
        edges = [
            {
                "source": parent,
                "target": node_id,
                "relation_type": G.get_edge_data(parent, node_id)[0].get("relation_type", "unknown")
            }
            for parent in parents
        ]
        return jsonify({"nodes": nodes, "edges": edges})

    return app


if __name__ == "__main__":
    app = create_app("graph.pickle")
    app.run(debug=True)
