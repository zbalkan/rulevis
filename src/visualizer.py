import os
import pickle

from flask import Flask, jsonify, render_template_string, request, Response
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

    @app.route("/api/root", methods=["GET"])
    def get_root_node():
        root = '0'
        if root not in G:
            return jsonify({"error": "Root node not found"}), 404

        children = list(G.successors(root))
        all_ids = [root] + children
        nodes = [
            {
                "id": nid,
                **{k: v for k, v in G.nodes[nid].items() if k != "expandable"},
                "is_expanded": (nid == root),
                "expandable": False if nid == root else (G.out_degree(nid) > 0)
            }
            for nid in all_ids
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
    def get_node_children(node_id: str):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        # Get the set of displayed IDs from the query string.
        displayed: set[str] = set(request.args.get(
            "displayed", "").split(",")) - {""}

        children = list(G.successors(node_id))

        nodes: list[dict] = []
        for nid in [node_id] + children:
            # Determine undisplayed children for the node
            expandable = len([child for child in G.successors(
                nid) if child not in displayed]) > 0

            attributes = G.nodes[nid].items()
            node_data = {
                "id": nid,
                **{k: v for k, v in attributes if k != "expandable"},
                "expandable": expandable
            }
            nodes.append(node_data)

        edges = [
            {
                "source": node_id,
                "target": child,
                "relation_type": G.get_edge_data(node_id, child)[0].get("relation_type", "unknown")
            }
            for child in children
        ]
        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/api/connections", methods=["POST"])
    def get_connections_between_nodes():
        # Get the list of node IDs from the request body.
        node_ids = request.json.get("ids", [])
        if not node_ids:
            return jsonify({"nodes": [], "edges": []})

        # Create a subgraph containing only the nodes present on the user's screen.
        subgraph = G.subgraph(node_ids)

        # Find all edges within this subgraph.
        edges = [
            {
                "source": u,
                "target": v,
                "relation_type": data.get("relation_type", "unknown")
            }
            for u, v, data in subgraph.edges(data=True)
        ]

        # Return only the edges. The nodes are already on the client.
        return jsonify({"nodes": [], "edges": edges})

    @app.route("/api/details/<node_id>", methods=["GET"])
    def get_node_details(node_id: str):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        node_data = G.nodes[node_id]

        # Find all parents from the master graph
        parents = [
            {
                "id": parent_id,
                "relation_type": G.get_edge_data(parent_id, node_id)[0].get("relation_type", "unknown")
            }
            for parent_id in G.predecessors(node_id)
        ]

        # Find all children from the master graph
        children = [
            {
                "id": child_id,
                "relation_type": G.get_edge_data(node_id, child_id)[0].get("relation_type", "unknown")
            }
            for child_id in G.successors(node_id)
        ]

        response = {
            "id": node_id,
            "description": node_data.get("description"),
            "groups": node_data.get("groups", []),
            "parents": parents,
            "children": children
        }

        return jsonify(response)

    @app.route("/api/search/<node_id>", methods=["GET"])
    def search_for_node(node_id: str):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        # Get the set of IDs the client already has on screen.
        displayed: set[str] = set(request.args.get("displayed", "").split(",")) - {""}

        # 1. Get the data for the node we searched for.
        node_data = G.nodes[node_id]
        nodes_to_return = [{
            "id": node_id,
            **{k: v for k, v in node_data.items() if k != "expandable"},
            # We can calculate 'expandable' here as well.
            "expandable": any(child not in displayed for child in G.successors(node_id))
        }]

        # 2. Find all parents and children of the searched node.
        parents = G.predecessors(node_id)
        children = G.successors(node_id)

        # 3. Filter edges: only include edges that connect to a node already on screen.
        edges_to_return = []
        for parent_id in parents:
            if parent_id in displayed:
                edges_to_return.append({
                    "source": parent_id,
                    "target": node_id,
                    "relation_type": G.get_edge_data(parent_id, node_id)[0].get("relation_type", "unknown")
                })
        
        for child_id in children:
            if child_id in displayed:
                edges_to_return.append({
                    "source": node_id,
                    "target": child_id,
                    "relation_type": G.get_edge_data(node_id, child_id)[0].get("relation_type", "unknown")
                })

        return jsonify({"nodes": nodes_to_return, "edges": edges_to_return})

    @app.route("/api/batch-nodes", methods=["POST"])
    def get_batch_nodes()->  Response:
        data = request.json
        if data is None:
            return Response()

        node_ids: list[str] = data.get("ids", [])
        displayed_ids = data.get("displayed", '').split(',')

        if not node_ids:
            return jsonify({"nodes": [], "edges": []})

        # Get the node data for all requested IDs.
        nodes_data = [
            {
                "id": nid,
                **{k: v for k, v in G.nodes[nid].items() if k != "expandable"},
                # We will let the client recalculate the 'expandable' state.
            }
            for nid in node_ids if nid in G
        ]

        # Find all edges connecting the new nodes to the already displayed nodes.
        # This includes edges between the new nodes themselves.
        all_relevant_nodes = set(node_ids).union(displayed_ids)
        
        subgraph = G.subgraph(all_relevant_nodes)
        
        edges_data = [
            {
                "source": u,
                "target": v,
                "relation_type": d.get("relation_type", "unknown")
            }
            for u, v, d in subgraph.edges(data=True) if u in node_ids or v in node_ids
        ]

        return jsonify({"nodes": nodes_data, "edges": edges_data})

    return app
