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
                body { font-family: sans-serif; }
                circle { cursor: pointer; }
                line { stroke-opacity: 0.6; }
                svg { width: 100%; height: 90vh; border: 1px solid #ccc; }
                .tooltip {
                    position: absolute;
                    text-align: center;
                    padding: 4px;
                    font: 12px sans-serif;
                    background: lightgray;
                    border: 0px;
                    border-radius: 4px;
                    pointer-events: none;
                }
            </style>
        </head>
        <body>
        <h2>Interactive Rule Graph Explorer</h2>
        <svg></svg>
        <div id=\"tooltip\" class=\"tooltip\" style=\"opacity:0\"></div>
        <script>
            const svg = d3.select("svg");
            const tooltip = d3.select("#tooltip");
            const width = window.innerWidth;
            const height = window.innerHeight * 0.9;

            const simulation = d3.forceSimulation()
                .force("link", d3.forceLink().id(d => d.id).distance(120))
                .force("charge", d3.forceManyBody().strength(-300))
                .force("center", d3.forceCenter(width / 2, height / 2));

            let nodes = [];
            let links = [];

            function updateGraph(newNodes, newLinks) {
                newNodes.forEach(n => {
                    if (!nodes.some(existing => existing.id === n.id)) {
                        nodes.push(n);
                    }
                });

                newLinks.forEach(l => {
                    if (!links.some(existing => existing.source === l.source && existing.target === l.target)) {
                        links.push(l);
                    }
                });

                const fullLinks = links.map(l => ({
                    ...l,
                    source: nodes.find(n => n.id === l.source),
                    target: nodes.find(n => n.id === l.target)
                }));

                const link = svg.selectAll("line")
                    .data(fullLinks, d => d.source.id + '-' + d.target.id);

                link.enter()
    .append("line")
    .attr("stroke", d => d.color || "#999");

                const node = svg.selectAll("g.node")
                    .data(nodes, d => d.id);

                const nodeEnter = node.enter().append("g")
                    .attr("class", "node")
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended))
                    .on("dblclick", (event, d) => expandNode(d.id))
                    .on("mouseover", (event, d) => {
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html(
    `ID: ${d.id}<br>` +
    `Description: ${d.description || 'N/A'}<br>` +
    `Groups: ${(d.groups || []).join(', ')}`
)
.style("left", (event.pageX + 5) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", () => {
                        tooltip.transition().duration(500).style("opacity", 0);
                    });

                nodeEnter.append("circle")
    .attr("r", 10)
    .attr("fill", d => d.color || "steelblue");

                nodeEnter.append("text")
    .attr("x", 12)
    .attr("dy", ".35em")
    .text(d => `${d.id}`);

                simulation.nodes(nodes).on("tick", () => {
                    svg.selectAll("line")
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);

                    svg.selectAll("g.node")
                        .attr("transform", d => `translate(${d.x},${d.y})`);
                });

                simulation.force("link").links(fullLinks);
                simulation.alpha(1).restart();
            }

            function loadInitialGraph() {
                fetch("/api/root")
                    .then(res => res.json())
                    .then(data => {
                        const newNodes = Object.entries(data.metadata).map(([id, meta]) => ({ id, ...meta }));
                        const newLinks = data.children.map(child => ({
                            source: data.root,
                            target: child,
                            color: "black"
                        }));
                        updateGraph(newNodes, newLinks);
                    })
                    .catch(error => console.error("Error loading root graph:", error));
            }

            function expandNode(nodeId) {
                fetch(`/api/node/${nodeId}`)
                    .then(res => res.json())
                    .then(data => {
                        const newNodes = Object.entries(data.metadata).map(([id, meta]) => ({ id, ...meta }));
                        updateGraph(newNodes, data.edges);
                    });
            }

            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            loadInitialGraph();
        </script>

        </body>
        </html>
        """)

    @app.route("/api/root", methods=["GET"])
    def get_root_node():
        root = '0'
        if root not in G:
            return jsonify({"error": "Root node not found"}), 404

        children = list(G.successors(root))
        metadata = {nid: G.nodes[nid] for nid in [root] + children}

        return jsonify({
            "root": root,
            "children": children,
            "metadata": metadata
        })

    @app.route("/api/node/<node_id>", methods=["GET"])
    def get_node_children(node_id):
        if node_id not in G:
            return jsonify({"error": f"Node '{node_id}' not found"}), 404

        children = list(G.successors(node_id))
        edges = [
            {
                "source": node_id,
                "target": child,
                "color": G.get_edge_data(node_id, child)[0].get("color", "black")
            } for child in children
        ]
        metadata = {nid: G.nodes[nid] for nid in [node_id] + children}

        return jsonify({
            "node": node_id,
            "children": children,
            "edges": edges,
            "metadata": metadata
        })

    return app
