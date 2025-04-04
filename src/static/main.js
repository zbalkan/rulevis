const svg = d3.select("svg");
const container = svg.append("g");

const zoom = d3.zoom()
    .scaleExtent([0.1, 5])
    .on("zoom", (event) => {
        container.attr("transform", event.transform);
    });

svg.call(zoom);

document.getElementById("resetZoom").addEventListener("click", () => {
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
});

const tooltip = d3.select("#tooltip");
const width = window.innerWidth;
const height = window.innerHeight * 0.9;

const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-120))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .velocityDecay(0.4);

let nodes = [];
let links = [];

function updateGraph(newNodes, newLinks) {
    newNodes.forEach(n => {
        if (!nodes.some(existing => existing.id === n.id)) {
            // Try to anchor new node near its parent if possible
            const parent = links.find(l => l.target === n.id);
            if (parent) {
                const parentNode = nodes.find(p => p.id === parent.source);
                if (parentNode && parentNode.x != null && parentNode.y != null) {
                    n.x = parentNode.x + Math.random() * 20 - 10;
                    n.y = parentNode.y + Math.random() * 20 - 10;
                }
            }
            n.is_expanded = n.is_expanded || false;
            n.color = (n.has_children && !n.is_expanded) ? "steelblue" : "grey";
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

    const link = container.selectAll("line")
        .data(fullLinks, d => d.source.id + '-' + d.target.id);

    link.enter()
        .insert("line", ":first-child")
        .attr("stroke", d => d.color || "#999")
        .on("mouseover", (event, d) => {
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`Relation: ${d.relation_type || 'unknown'}`)
                .style("left", (event.pageX + 5) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", () => {
            tooltip.transition().duration(500).style("opacity", 0);
        });

    const node = container.selectAll("g.node")
        .data(nodes, d => d.id);

    const nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended))
        .on("dblclick", (event, d) => {
            if (d.has_children) {
                expandNode(d.id);
            }
        })
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
        .attr("fill", "#ffffff")
        .text(d => `${d.id}`);

    // UPDATE existing node colors if needed
    container.selectAll("g.node").select("circle")
        .attr("fill", d => d.color || "steelblue");

    simulation.nodes(nodes).on("tick", () => {
        container.selectAll("line")
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        container.selectAll("g.node")
            .attr("transform", d => `translate(${d.x},${d.y})`);
    });

    simulation.force("link").links(fullLinks);
    simulation.alphaTarget(0.2).restart();
}

function loadInitialGraph() {
    fetch("/api/root")
        .then(res => res.json())
        .then(data => {
            updateGraph(data.nodes, data.edges);
        });
}

function expandNode(nodeId) {
    fetch(`/api/node/${nodeId}`)
        .then(res => res.json())
        .then(data => {
            const nodeToUpdate = nodes.find(n => n.id === nodeId);
            if (nodeToUpdate) {
                nodeToUpdate.is_expanded = true;
                nodeToUpdate.color = "grey";
                nodeToUpdate.has_children = false;
            }

            updateGraph(data.nodes, data.edges);
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
    d.fx = d.x;
    d.fy = d.y;
}

loadInitialGraph();