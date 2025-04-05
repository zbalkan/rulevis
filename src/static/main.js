const svg = d3.select("svg");
const container = svg.append("g");

const zoom = d3.zoom()
    .scaleExtent([0.1, 5])
    .on("zoom", (event) => {
        container.attr("transform", event.transform);
    });

svg.call(zoom);

// Reset zoom button handler
document.getElementById("resetZoom").addEventListener("click", () => {
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
});

// Reset graph button handler
document.getElementById("resetGraph").addEventListener("click", () => {
    // Stop simulation and clear forces
    simulation.stop();
    simulation.nodes([]);
    simulation.force("link").links([]);
    simulation.on("tick", null);

    // Clear graph data and SVG elements
    nodes.length = 0;
    links.length = 0;
    container.selectAll("*").remove();

    // Reset zoom to default view
    svg.transition().duration(500).call(
        zoom.transform,
        d3.zoomIdentity
    );

    // Reload from root node
    loadInitialGraph();
});

const tooltip = d3.select("#tooltip");
let tooltipTimeout;
const TOOLTIP_SHOW_DELAY = 500;      // ms delay before showing tooltip
const TOOLTIP_HIDE_DURATION = 300;   // ms to fade out tooltip
const TOOLTIP_SHOW_DURATION = 200;   // ms to fade in tooltip

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

    // Update edges: assign semantic classes based on relation_type
    const link = container.selectAll("line")
        .data(fullLinks, d => d.source.id + '-' + d.target.id);

    link.enter()
        .insert("line", ":first-child")
        .attr("class", d => `edge edge-${d.relation_type || 'unknown'}`)
        .on("mouseover", (event, d) => {
            tooltipTimeout = setTimeout(() => {
                tooltip.transition().duration(TOOLTIP_SHOW_DURATION).style("opacity", 0.9);
                tooltip.html(`Relation: ${d.relation_type || 'unknown'}`)
                    .style("left", (event.pageX + 5) + "px")
                    .style("top", (event.pageY - 28) + "px");
            }, TOOLTIP_SHOW_DELAY);
        })
        .on("mouseout", () => {
            clearTimeout(tooltipTimeout);
            tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
        });

    // Update nodes: assign semantic classes based on node_type
    const node = container.selectAll("g.node")
        .data(nodes, d => d.id);

    const nodeEnter = node.enter().append("g")
        .attr("class", "node")
        // Double-click: clear highlight and expand node if applicable
        .on("dblclick", (event, d) => {
            event.stopPropagation();
            clearHighlight();
            if (d.has_children) {
                expandNode(d.id);
            }
        })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended))
        .on("mouseover", (event, d) => {
            tooltipTimeout = setTimeout(() => {
                tooltip.transition().duration(TOOLTIP_SHOW_DURATION).style("opacity", 0.9);
                tooltip.html(
                    `ID: ${d.id}<br>` +
                    `Description: ${d.description || 'N/A'}<br>` +
                    `Groups: ${(d.groups || []).join(', ')}`
                )
                    .style("left", (event.pageX + 5) + "px")
                    .style("top", (event.pageY - 28) + "px");
            }, TOOLTIP_SHOW_DELAY);
        })
        .on("mouseout", () => {
            clearTimeout(tooltipTimeout);
            tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
        });

    nodeEnter.append("circle")
        .attr("class", d => `circle ${d.node_type ? 'node-' + d.node_type : 'node-default'}`)
        .attr("r", 10);

    nodeEnter.append("text")
        .attr("x", 12)
        .attr("dy", ".35em")
        .text(d => `${d.id}`);

    // Update existing node classes if needed
    container.selectAll("g.node").select("circle")
        .attr("class", d => `circle ${d.node_type ? 'node-' + d.node_type : 'node-default'}`);

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
                nodeToUpdate.node_type = "default";
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

// ----- Search Functionality -----
function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;

    const foundNode = nodes.find(n => n.id === searchInput);
    // Clear any existing highlights and resume simulation in case it was paused
    clearHighlight();

    if (foundNode) {
        // Add a highlight class to the found node
        container.selectAll("g.node")
            .filter(d => d.id === foundNode.id)
            .classed("highlight", true);

        // Pause simulation during highlighting
        simulation.stop();

        // Pan to center the found node if its coordinates are available
        if (foundNode.x != null && foundNode.y != null) {
            svg.transition().duration(750)
                .call(zoom.transform, d3.zoomIdentity.translate(width / 2 - foundNode.x, height / 2 - foundNode.y));
        }
    } else {
        alert("Node not found: " + searchInput);
    }
}

document.getElementById("searchBtn").addEventListener("click", function (event) {
    event.stopPropagation();
    handleSearch();
});
document.getElementById("searchBox").addEventListener("keyup", (event) => {
    if (event.key === "Enter") {
        event.stopPropagation();
        handleSearch();
    }
});

// ----- Highlight Reset Logic -----
function clearHighlight() {
    container.selectAll("g.node").classed("highlight", false);
    // Resume simulation when highlight is cleared
    simulation.restart();
}

// Global click handler: if user clicks anywhere that is not a search element or a highlighted node, clear the highlight.
document.addEventListener("click", function (event) {
    const target = event.target;
    // Do not clear if click is on the search box or button
    if (target.id === "searchBtn" || target.id === "searchBox") return;
    // Check if the click target is inside a node element with the "highlight" class.
    const highlightedNode = target.closest("g.node.highlight");
    if (!highlightedNode) {
        clearHighlight();
    }
});

// Initial graph load
loadInitialGraph();
