// Global set to track displayed rule IDs
let displayedRuleIDs = new Set();
// Flag to indicate if the context menu is open (freeze state)
let contextMenuOpen = false;

const svg = d3.select("svg");
const container = svg.append("g");

const zoom = d3.zoom()
    .scaleExtent([0.1, 5])
    .on("zoom", (event) => {
        container.attr("transform", event.transform);
    });
svg.call(zoom);

// Block right-click context menu on SVG canvas if not clicking on a node.
svg.on("contextmenu", function (event) {
    if (!event.target.closest("g.node")) {
        event.preventDefault();
    }
});

// Reset zoom button handler
document.getElementById("resetZoom").addEventListener("click", () => {
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
});

// Reset graph button handler
document.getElementById("resetGraph").addEventListener("click", () => {
    simulation.stop();
    simulation.nodes([]);
    simulation.force("link").links([]);
    simulation.on("tick", null);
    nodes.length = 0;
    links.length = 0;
    container.selectAll("*").remove();
    displayedRuleIDs.clear();
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
    loadInitialGraph();
});

// Rearrange Graph button handler
document.getElementById("rearrangeGraph").addEventListener("click", () => {
    // Release pinned positions for all nodes.
    nodes.forEach(d => {
        d.fx = null;
        d.fy = null;
    });
    // Reheat the simulation so the layout recalculates.
    simulation.alpha(1).restart();
});

const tooltip = d3.select("#tooltip");
let tooltipTimeout;
const TOOLTIP_SHOW_DELAY = 500;
const TOOLTIP_HIDE_DURATION = 300;
const TOOLTIP_SHOW_DURATION = 200;

const width = window.innerWidth;
const height = window.innerHeight * 0.9;

const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-120))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .velocityDecay(0.4);

let nodes = [];
let links = [];

// Helper function to hide tooltip
function hideTooltip() {
    clearTimeout(tooltipTimeout);
    tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
}

// (Helper areParentsDisplayed remains available if needed.)
function areParentsDisplayed(node) {
    if (node.parent_ids && node.parent_ids.length > 0) {
        return node.parent_ids.every(pid => displayedRuleIDs.has(pid));
    } else {
        return displayedRuleIDs.has("0");
    }
}

// Create custom context menu element (initially hidden)
const contextMenu = d3.select("body").append("div")
    .attr("id", "contextMenu")
    .style("position", "absolute")
    .style("display", "none")
    .style("background-color", "#333")
    .style("color", "#eee")
    .style("padding", "5px")
    .style("border", "1px solid #888")
    .style("border-radius", "4px")
    .style("z-index", 1000);

function updateGraph(newNodes, newLinks) {
    newNodes.forEach(n => {
        if (!nodes.some(existing => existing.id === n.id)) {
            const parent = links.find(l => l.target === n.id);
            if (parent) {
                const parentNode = nodes.find(p => p.id === parent.source);
                if (parentNode && parentNode.x != null && parentNode.y != null) {
                    n.x = parentNode.x + Math.random() * 20 - 10;
                    n.y = parentNode.y + Math.random() * 20 - 10;
                }
            }
            n.is_expanded = n.is_expanded || false;
            n.parents_expanded = n.parents_expanded || false;
            nodes.push(n);
            displayedRuleIDs.add(n.id);
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
        .attr("class", d => `edge edge-${d.relation_type || 'unknown'}`)
        .on("mouseover", (event, d) => {
            if (contextMenuOpen) return;
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

    const node = container.selectAll("g.node")
        .data(nodes, d => d.id);

    const nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .on("contextmenu", (event, d) => {
            event.preventDefault();
            event.stopPropagation();
            hideTooltip();
            showContextMenu(event, d);
        })
        .on("dblclick", (event, d) => {
            event.stopPropagation();
            hideContextMenu();
            clearHighlight();
            if (d.has_children) {
                expandNode(d.id);
            }
        })
        .call(d3.drag()
            .filter(function (event) { return event.button === 0; })
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended))
        .on("mouseover", (event, d) => {
            if (contextMenuOpen) return;
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
    // Pass the current displayed IDs to the backend
    fetch(`/api/node/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(res => res.json())
        .then(data => {
            const nodeToUpdate = nodes.find(n => n.id === nodeId);
            if (nodeToUpdate) {
                nodeToUpdate.is_expanded = true;
                nodeToUpdate.node_type = "default";  // Force default when children are expanded
                nodeToUpdate.has_children = data.nodes.find(n => n.id === nodeId).has_children;
            }
            updateGraph(data.nodes, data.edges);
        });
}

function expandParents(nodeId) {
    fetch(`/api/parents/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(res => res.json())
        .then(data => {
            const targetNode = nodes.find(n => n.id === nodeId);
            if (targetNode) {
                targetNode.parents_expanded = true;
            }
            updateGraph(data.nodes, data.edges);
        });
}

function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    // Optionally, don't pin the nodes permanently; let them float until rearranged.
    // d.fx and d.fy are kept until rearrangement is triggered.
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    // Here we leave d.fx and d.fy as they are (pinned)
    // so that nodes remain at the dragged position until "rearrange" is triggered.
}

function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;
    const foundNode = nodes.find(n => n.id === searchInput);
    clearHighlight();
    if (foundNode) {
        container.selectAll("g.node")
            .filter(d => d.id === foundNode.id)
            .classed("highlight", true);
        simulation.stop();
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
    simulation.restart();
}

// Helper: Return comma-separated list of displayed node IDs.
function getDisplayedIds() {
    return Array.from(displayedRuleIDs).join(",");
}

// ----- Custom Context Menu Logic -----
function showContextMenu(event, d) {
    simulation.stop();
    contextMenuOpen = true;
    hideTooltip();
    contextMenu.html("");

    // "Show children" menu item - created disabled initially
    const showChildrenItem = contextMenu.append("div")
        .text("Show children")
        .style("padding", "5px")
        .style("cursor", "pointer")
        .style("opacity", 0.5)
        .style("pointer-events", "none")
        .on("click", () => {
            hideContextMenu();
            if (d.has_children) {
                expandNode(d.id);
            }
        });
    if (d.has_children) {
        fetch(`/api/node/${d.id}?displayed=${getDisplayedIds()}`)
            .then(res => res.json())
            .then(data => {
                let updatedState = data.nodes.find(n => n.id === d.id);
                d.has_children = updatedState.has_children;
                d.node_type = updatedState.node_type;
                if (d.has_children) {
                    showChildrenItem.style("opacity", 1)
                        .style("pointer-events", "auto");
                } else {
                    showChildrenItem.style("opacity", 0.5)
                        .style("pointer-events", "none");
                }
            })
            .catch(error => {
                console.error("Error fetching children: ", error);
            });
    }

    // "Show parents" menu item - created disabled initially
    const showParentsItem = contextMenu.append("div")
        .text("Show parents")
        .style("padding", "5px")
        .style("cursor", "pointer")
        .style("opacity", 0.5)
        .style("pointer-events", "none")
        .on("click", () => {
            hideContextMenu();
            if (d.id !== "0" && !d.parents_expanded) {
                expandParents(d.id);
            }
        });
    if (!d.parents_expanded) {
        fetch(`/api/parents/${d.id}?displayed=${getDisplayedIds()}`)
            .then(res => res.json())
            .then(data => {
                let parentIDs = data.nodes.filter(n => n.id !== d.id).map(n => n.id);
                if (parentIDs.length > 1) {
                    parentIDs = parentIDs.filter(pid => pid !== "0");
                }
                const allDisplayed = parentIDs.every(pid => displayedRuleIDs.has(pid));
                if (!allDisplayed) {
                    showParentsItem.style("opacity", 1)
                        .style("pointer-events", "auto");
                }
            })
            .catch(error => {
                console.error("Error fetching parents: ", error);
            });
    }

    contextMenu.style("left", event.pageX + "px")
        .style("top", event.pageY + "px")
        .style("display", "block");
}

function hideContextMenu() {
    contextMenu.style("display", "none");
    if (contextMenuOpen) {
        simulation.restart();
        contextMenuOpen = false;
    }
}

// Global click handler to hide context menu and reset highlight if clicking outside
document.addEventListener("click", function (event) {
    const target = event.target;
    if (target.id === "searchBtn" || target.id === "searchBox") return;
    if (!target.closest("#contextMenu")) {
        hideContextMenu();
    }
    const highlightedNode = target.closest("g.node.highlight");
    if (!highlightedNode) {
        clearHighlight();
    }
});

function buildLegend() {
    // Node Legend Data: Using our CSS classes for nodes.
    const nodeLegendData = [
        { label: "Expandable Node", class: "node-expandable" },
        { label: "Default Node", class: "node-default" }
    ];

    // Append a group for the node legend. Adjust position as needed.
    const nodeLegend = svg.append("g")
        .attr("class", "node-legend")
        .attr("transform", "translate(20,20)");

    const nodeLegendItems = nodeLegend.selectAll(".node-legend-item")
        .data(nodeLegendData)
        .enter()
        .append("g")
        .attr("class", "node-legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    // Append a circle that takes its style from the CSS class.
    nodeLegendItems.append("circle")
        .attr("r", 8)
        .attr("class", d => d.class);

    // Append text next to the circle.
    nodeLegendItems.append("text")
        .attr("x", 15)
        .attr("y", 5)
        .text(d => d.label)
        .attr("fill", "#eee")
        .attr("font-size", "14px");

    // Edge Legend Data: Use CSS classes defined for edges.
    const edgeLegendData = [
        { label: "if_sid", class: "edge-if_sid" },
        { label: "if_matched_sid", class: "edge-if_matched_sid" },
        { label: "if_group", class: "edge-if_group" },
        { label: "if_matched_group", class: "edge-if_matched_group" },
        { label: "No parent", class: "edge-no_parent" },
        { label: "Unknown", class: "edge-unknown" }
    ];

    // Append a group for the edge legend. Adjust vertical position as needed.
    const edgeLegend = svg.append("g")
        .attr("class", "edge-legend")
        .attr("transform", "translate(20,100)");

    const edgeLegendItems = edgeLegend.selectAll(".edge-legend-item")
        .data(edgeLegendData)
        .enter()
        .append("g")
        .attr("class", "edge-legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    // Append a line to represent the edge. The stroke is defined by the CSS class.
    edgeLegendItems.append("line")
        .attr("x1", 0)
        .attr("y1", 8)
        .attr("x2", 30)
        .attr("y2", 8)
        .attr("class", d => d.class)
        .attr("stroke-width", 4);

    // Append text next to the line.
    edgeLegendItems.append("text")
        .attr("x", 40)
        .attr("y", 12)
        .text(d => d.label)
        .attr("fill", "#eee")
        .attr("font-size", "14px");
}

// Call buildLegend() after the graph loads.
buildLegend();

// Initial graph load
loadInitialGraph();
