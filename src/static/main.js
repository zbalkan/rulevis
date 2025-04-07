// Tutorial Modal Function
function showTutorial() {
    const overlay = document.createElement("div");
    overlay.id = "tutorialOverlay";
    overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.8);
    z-index: 2000;
    display: flex;
    align-items: center;
    justify-content: center;
  `;

    const messageBox = document.createElement("div");
    messageBox.id = "tutorialMessageBox";
    messageBox.style.cssText = `
    background: #333;
    color: #eee;
    padding: 20px;
    border-radius: 8px;
    width: 80%;
    max-width: 600px;
    text-align: left;
    font-family: 'Segoe UI', 'DejaVu Sans', Arial, sans-serif;
  `;

    messageBox.innerHTML = `
    <h2>Welcome to Rule Graph Explorer</h2>
    <p>This tool allows you to visualize rules as nodes in a graph.</p>
    <ul>
      <li><strong>Nodes:</strong> Represent individual rules.
        <ul>
          <li><span class="node-expandable" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:steelblue;margin-right:4px;"></span>
              Expandable (has children)</li>
          <li><span class="node-default" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:grey;margin-right:4px;"></span>
              Default (leaf node)</li>
        </ul>
      </li>
      <li><strong>Right-click</strong> on a node to open a context menu with options (e.g. expand children or parents).</li>
      <li><strong>Double-click</strong> on a node to expand its children.</li>
      <li><strong>Pause simulation:</strong> Hold <strong>Space</strong> or <strong>CTRL</strong> to pause the force simulation, then release to resume.</li>
      <li><strong>Warning:</strong> Expanding too many nodes may make the graph complex and slow down the simulation.</li>
    </ul>
    <button id="tutorialCloseButton" style="padding:8px 16px;border:none;border-radius:4px;background:#444;color:#eee;cursor:pointer;">
      Got it
    </button>
  `;

    overlay.appendChild(messageBox);
    document.body.appendChild(overlay);

    document.getElementById("tutorialCloseButton").addEventListener("click", () => {
        overlay.parentNode.removeChild(overlay);
    });
}

// Show tutorial when the document content is loaded.
document.addEventListener("DOMContentLoaded", showTutorial);

// ----- Graph Visualization Logic -----
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
    // 1. Merge or add nodes
    newNodes.forEach(newNode => {
        const existingNode = nodes.find(node => node.id === newNode.id);
        if (existingNode) {
            // Update key properties so the node's color/state changes if needed
            existingNode.has_children = newNode.has_children;
            existingNode.node_type = newNode.node_type;
            // Optionally merge other fields like description, groups, etc.
            existingNode.description = newNode.description;
            existingNode.groups = newNode.groups;
        } else {
            // If it's a brand-new node, try to place it near its parent if known
            const parentLink = links.find(l => l.target === newNode.id);
            if (parentLink) {
                const parentNode = nodes.find(n => n.id === parentLink.source);
                if (parentNode && parentNode.x != null && parentNode.y != null) {
                    newNode.x = parentNode.x + Math.random() * 20 - 10;
                    newNode.y = parentNode.y + Math.random() * 20 - 10;
                }
            }
            // Initialize additional state
            newNode.is_expanded = newNode.is_expanded || false;
            newNode.parents_expanded = newNode.parents_expanded || false;
            nodes.push(newNode);
            displayedRuleIDs.add(newNode.id);
        }
    });

    // 2. Merge or add links
    newLinks.forEach(l => {
        const exists = links.some(
            existing => existing.source === l.source && existing.target === l.target
        );
        if (!exists) {
            links.push(l);
        }
    });

    // 3. Create a mapped version of links with node objects as source/target
    const fullLinks = links.map(l => ({
        ...l,
        source: nodes.find(n => n.id === l.source),
        target: nodes.find(n => n.id === l.target)
    }));

    // 4. Node selection/enter/exit
    const nodeSelection = container.selectAll("g.node")
        .data(nodes, d => d.id);

    // Remove old nodes that no longer exist in 'nodes'
    nodeSelection.exit().remove();

    // Enter selection for new nodes
    const nodeEnter = nodeSelection.enter().append("g")
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
        .attr("r", 10)
        .attr("class", d => `circle ${d.node_type ? 'node-' + d.node_type : 'node-default'}`);

    nodeEnter.append("text")
        .attr("x", 12)
        .attr("dy", ".35em")
        .text(d => d.id);

    // Update existing + new nodes in the DOM (to refresh CSS classes, etc.)
    const allNodes = nodeEnter.merge(nodeSelection);
    allNodes.select("circle")
        .attr("class", d => `circle ${d.node_type ? 'node-' + d.node_type : 'node-default'}`);

    // 5. Link selection/enter/exit
    const linkSelection = container.selectAll("line")
        .data(fullLinks, d => d.source.id + "-" + d.target.id);

    linkSelection.exit().remove();

    linkSelection.enter()
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

    // 6. Update the simulation with the new node/link arrays
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
    // Call API with current displayed node IDs.
    fetch(`/api/node/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(res => res.json())
        .then(data => {
            // Immediately add all returned nodes to the displayed set.
            data.nodes.forEach(n => displayedRuleIDs.add(n.id));

            // Force the parent's state to default (grey) right away.
            const parentFromResponse = data.nodes.find(n => n.id === nodeId);
            if (parentFromResponse) {
                parentFromResponse.is_expanded = true;
                parentFromResponse.node_type = "default";  // Force to default
                parentFromResponse.has_children = false;     // Assume all children are now displayed
            }

            // Update the graph with the API response.
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

    // Try to find the node in the current graph.
    let foundNode = nodes.find(n => n.id === searchInput);
    if (foundNode) {
        // Node exists in the canvas. Highlight it.
        container.selectAll("g.node")
            .filter(d => d.id === foundNode.id)
            .classed("highlight", true);
        simulation.stop();
        if (foundNode.x != null && foundNode.y != null) {
            svg.transition().duration(750)
                .call(zoom.transform, d3.zoomIdentity.translate(width / 2 - foundNode.x, height / 2 - foundNode.y));
        }
    } else {
        // Node not in current graph. Query the backend.
        fetch(`/api/node/${searchInput}?displayed=${getDisplayedIds()}`)
            .then(res => res.json())
            .then(data => {
                // Check if the returned data contains the searched node.
                foundNode = data.nodes.find(n => n.id === searchInput);
                if (foundNode) {
                    // Update the graph with the newly returned nodes and edges.
                    updateGraph(data.nodes, data.edges);
                    // Highlight the node once it's added.
                    container.selectAll("g.node")
                        .filter(d => d.id === searchInput)
                        .classed("highlight", true);
                    simulation.stop();
                    if (foundNode.x != null && foundNode.y != null) {
                        svg.transition().duration(750)
                            .call(zoom.transform, d3.zoomIdentity.translate(width / 2 - foundNode.x, height / 2 - foundNode.y));
                    }
                } else {
                    alert("Node not found: " + searchInput);
                }
            })
            .catch(error => {
                console.error("Error fetching node: ", error);
                alert("Error fetching node: " + searchInput);
            });
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

// Flag to indicate if simulation is paused via keyboard
let simulationPausedByKey = false;

document.addEventListener("keydown", (event) => {
    // Check for Space key (key code "Space") or CTRL key (event.ctrlKey)
    if (event.code === "Space" || event.ctrlKey) {
        if (!simulationPausedByKey) {
            simulationPausedByKey = true;
            simulation.stop();
        }
    }
});

document.addEventListener("keyup", (event) => {
    // On keyup, if space or ctrl is released, resume simulation
    if (simulationPausedByKey && (event.code === "Space" || !event.ctrlKey)) {
        simulationPausedByKey = false;
        simulation.alpha(1).restart();
    }
});

// Initial graph load
loadInitialGraph();



// ----- Legend Building Logic -----
// Function to build the legend for nodes and edges
function buildLegend() {
    // --- Node Legend ---
    const nodeLegendData = [
        { label: "Expandable Node", class: "node-expandable" },
        { label: "Default Node", class: "node-default" }
    ];

    // Append a group for the node legend at a fixed position.
    const nodeLegend = svg.append("g")
        .attr("class", "legend node-legend")
        .attr("transform", "translate(20,20)");

    const nodeLegendItems = nodeLegend.selectAll(".legend-item")
        .data(nodeLegendData)
        .enter()
        .append("g")
        .attr("class", "legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    // Append a circle for each node legend item. The circle gets its fill from your CSS.
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

    // --- Edge Legend ---
    const edgeLegendData = [
        { label: "if_sid", class: "edge-if_sid" },
        { label: "if_matched_sid", class: "edge-if_matched_sid" },
        { label: "if_group", class: "edge-if_group" },
        { label: "if_matched_group", class: "edge-if_matched_group" },
        { label: "No parent", class: "edge-no_parent" },
        { label: "Unknown", class: "edge-unknown" }
    ];

    // Append a group for the edge legend; position it below the node legend.
    const edgeLegend = svg.append("g")
        .attr("class", "legend edge-legend")
        .attr("transform", "translate(20,100)");

    const edgeLegendItems = edgeLegend.selectAll(".legend-item")
        .data(edgeLegendData)
        .enter()
        .append("g")
        .attr("class", "legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    // Append a line for each edge legend item.
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
