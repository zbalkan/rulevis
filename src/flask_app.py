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
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\">
            <title>Rule Graph Explorer</title>
            <script src=\"https://d3js.org/d3.v7.min.js\"></script>
            <style>
                body {
                    font-family: sans-serif;
                    margin: 0;
                    background-color: #121212;
                    color: #eee;
                }

                svg {
                    width: 100%;
                    height: 90vh;
                    background-color: #121212;
                    border: 1px solid #444;
                }

                .tooltip {
                    position: absolute;
                    text-align: left;
                    padding: 8px;
                    font: 12px sans-serif;
                    background: #333;
                    color: #eee;
                    border: 1px solid #888;
                    border-radius: 4px;
                    pointer-events: none;
                    opacity: 0;
                }

                button {
                    background: #333;
                    color: #eee;
                    border: 1px solid #888;
                    padding: 6px 12px;
                    border-radius: 4px;
                    cursor: pointer;
                }

                button:hover {
                    background: #444;
                }
                text {
                    user-select: none;
                }
            </style>

        </head>
        <body>
        <h2>Interactive Rule Graph Explorer</h2>
        <button id="resetZoom" style="margin: 10px;">Reset Zoom</button>
        <svg></svg>
        <div id=\"tooltip\" class=\"tooltip\"></div>
        <script src=\"static/main.js\"></script>
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
                **G.nodes[nid],
                "has_children": G.out_degree(nid) > 0,
                "is_expanded": nid == root,  # root starts expanded
                "color": "steelblue" if G.out_degree(nid) > 0 else "grey"
            }
            for nid in [root] + children
        ]

        edges = [
            {
                "source": root,
                "target": child,
                "color": "#171717",  # very light gray for visual de-emphasis
                "relation_type": "No parent object"
            }
            for child in children
        ]

        return jsonify({
            "nodes": nodes,
            "edges": edges
        })

    @app.route("/api/node/<node_id>", methods=["GET"])
    def get_node_children(node_id):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        children = list(G.successors(node_id))
        nodes = [
            {"id": nid, **G.nodes[nid], "has_children": G.out_degree(nid) > 0,
             "color": "steelblue" if G.out_degree(nid) > 0 else "grey"} for nid in [node_id] + children
        ]
        edges = [
            {
                "source": node_id,
                "target": child,
                "color": G.get_edge_data(node_id, child)[0].get("color", "black"),
                "relation_type": G.get_edge_data(node_id, child)[0].get("relation_type", "unknown")
            } for child in children
        ]

        return jsonify({
            "nodes": nodes,
            "edges": edges
        })

    return app
