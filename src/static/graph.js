// Toast notification code
// Simple toast notification implementation
function showNotification(message) {
    // Check if a notification div already exists
    let toast = document.getElementById("toastNotification");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toastNotification";
        toast.style.cssText = `
            position: fixed;
            top: 120px;
            right: 40px;
            background: #800404;
            color: #eee;
            padding: 10px 15px;
            border-radius: 4px;
            z-index: 3000;
            opacity: 0;
            transition: opacity 0.5s ease;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = 1;

    // Hide toast after 3 seconds
    setTimeout(() => {
        toast.style.opacity = 0;
    }, 3000);
}

// --- Wrapper for fetch calls ---
async function fetchJSON(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            if (response.status === 404) {
                showNotification("Not found.");
                throw new Error("Not Found");
            } else {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
        }
        return await response.json();
    } catch (error) {
        // For non-404 errors, show the "server not reachable" message.
        if (error.message !== "Not Found") {
            console.error("Fetch error at " + url, error);
            showNotification("Server not reachable. Please check your connection.");
        }
        throw error;
    }
}

// Helper functions for repositioning
function resetToRootPositions() {
    // Choose a smaller radius than the final desired radius, for example 20px
    const rootX = width / 2;
    const rootY = height / 2;
    nodes.forEach(n => {
        // Randomize a bit: place within a 20px radius around the center
        const angle = Math.random() * 2 * Math.PI;
        const r = Math.random() * 2;
        n.x = rootX + r * Math.cos(angle);
        n.y = rootY + r * Math.sin(angle);
        // Pin the node at that position.
        n.fx = n.x;
        n.fy = n.y;
    });
}

function releaseNodePins() {
    nodes.forEach(n => {
        n.fx = null;
        n.fy = null;
    });
}

/**
 * Common reposition function.
 * @param {boolean} clearExisting - If true, clear current graph and load only first-level nodes.
 *                                  If false, merge first-level nodes with already displayed nodes.
 */
function applyReposition(clearExisting) {
    // Fetch first-level children from virtual root.
    fetchJSON("/api/root")
        .then(data => {
            if (clearExisting) {
                // For reset: clear all current nodes, links, container, and displayed set.
                simulation.stop();
                simulation.nodes([]);
                simulation.force("link").links([]);
                simulation.on("tick", null);
                nodes = [];
                links = [];
                container.selectAll("*").remove();
                displayedRuleIDs.clear();
            }
            // update graph with the first-level nodes and edges.
            updateGraph(data.nodes, data.edges);
            // Reposition nodes to near the virtual root (with slight spread).
            resetToRootPositions();
            // After a short delay, release pins and restart simulation.
            setTimeout(() => {
                nodes.forEach(n => {
                    n.fx = null;
                    n.fy = null;
                });
                simulation.alpha(0.1).alphaDecay(0.2).restart();
            }, 300);
        })
        .catch(error => {
            // Error is handled in fetchJSON.
        });
}


// --- Helper for wrapping groups text ---
// Given an array of group names and a maximum length per line,
// this function joins them with a comma and inserts line breaks (<br>)
// when the current line exceeds the maximum length.
function wrapGroups(groups, maxLength) {
    // groups: array of strings, maxLength: maximum characters per line
    let result = "";
    let currentLine = "";
    groups.forEach((group) => {
        let addition = (currentLine === "" ? group : ", " + group);
        // If adding this group would exceed the max, start a new line.
        if (currentLine.length + addition.length > maxLength && currentLine !== "") {
            if (result !== "") {
                result += "<br>";
            }
            result += currentLine;
            currentLine = group; // start new line with current group
        } else {
            currentLine += addition;
        }
    });
    if (currentLine) {
        if (result !== "") {
            result += "<br>";
        }
        result += currentLine;
    }
    return result;
}

// New helper function to generate tooltip HTML as a table-like layout.
function getTooltipHTML(d) {
    // Use inline styles to remove borders and add spacing.
    const tableStyle = "border-collapse: collapse; width: 100%;";
    const keyStyle = "padding-right: 5px; font-weight: bold; vertical-align: top;";
    const valueStyle = "vertical-align: top;";
    // Wrap groups using your wrapGroups function (if available) or join them as needed.
    let groupsHTML = wrapGroups(d.groups || [], 40);
    // Alternatively, if wrapGroups isn't desired, you can use: (d.groups || []).join(", ")
    return `<table style="${tableStyle}">
                <tr>
                    <td style="${keyStyle}">ID:</td>
                    <td style="${valueStyle}">${d.id}</td>
                </tr>
                <tr>
                    <td style="${keyStyle}">Description:</td>
                    <td style="${valueStyle}">${d.description || "N/A"}</td>
                </tr>
                <tr>
                    <td style="${keyStyle}">Groups:</td>
                    <td style="${valueStyle}">${groupsHTML}</td>
                </tr>
            </table>`;
}
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

// Reset Graph: Display ONLY first-level children of virtual root.
document.getElementById("resetGraph").addEventListener("click", () => {
    // Use clearExisting = true
    applyReposition(true);
});

// Rearrange Graph: Display first-level children of virtual root
// PLUS the already displayed nodes (which remain in the nodes array).
document.getElementById("rearrangeGraph").addEventListener("click", () => {
    // Use clearExisting = false so that mergeNodes() preserves existing nodes.
    applyReposition(false);
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
    .force("charge", d3.forceManyBody().strength(-80))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("radial", d3.forceRadial(150, width / 2, height / 2).strength(0.15))
    .velocityDecay(0.2)
    .alphaDecay(0.1);

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

function updateCounter() {
    let counterDiv = document.getElementById("counter");
    if (!counterDiv) {
        counterDiv = document.createElement("div");
        counterDiv.id = "counter";
        // Style the counter to appear at the left bottom corner.
        counterDiv.style.position = "fixed";
        counterDiv.style.left = "10px";
        counterDiv.style.bottom = "10px";
        counterDiv.style.backgroundColor = "rgba(0, 0, 0, 0.6)";
        counterDiv.style.color = "#eee";
        counterDiv.style.padding = "5px 10px";
        counterDiv.style.borderRadius = "4px";
        counterDiv.style.fontFamily = "sans-serif";
        counterDiv.style.fontSize = "14px";
        document.body.appendChild(counterDiv);
    }
    // Update counter text: using the lengths of nodes and links arrays.
    counterDiv.textContent = `Nodes: ${nodes.length} | Edges: ${links.length}`;
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
    // Step 1: Merge new nodes and links into our data arrays.
    mergeNodes(newNodes);
    mergeLinks(newLinks);

    // Step 2: Build full link objects with node references.
    var fullLinks = links.map(function (l) {
        return {
            ...l,
            source: nodes.find(function (n) { return n.id === l.source; }),
            target: nodes.find(function (n) { return n.id === l.target; })
        };
    });

    // Step 3: Update the visualizations.
    updateNodes();
    updateLinks(fullLinks);
    updateSimulation(fullLinks);

    // Update counter display.
    updateCounter();
}
// Merges new nodes with existing nodes.
function mergeNodes(newNodes) {
    newNodes.forEach(function (newNode) {
        var existingNode = nodes.find(function (node) {
            return node.id === newNode.id;
        });
        if (existingNode) {
            // Update properties (only the ones that might change)
            existingNode.expandable = newNode.expandable;
            existingNode.description = newNode.description;
            existingNode.groups = newNode.groups;
        } else {
            // If new, try to place it near its parent if known.
            var parentLink = links.find(function (l) { return l.target === newNode.id; });
            if (parentLink) {
                var parentNode = nodes.find(function (n) { return n.id === parentLink.source; });
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
}

// Merges new links with existing links.
function mergeLinks(newLinks) {
    newLinks.forEach(function (l) {
        var exists = links.some(function (existing) {
            return existing.source === l.source && existing.target === l.target;
        });
        if (!exists) {
            links.push(l);
        }
    });
}

// Update nodes selection: handles enter, update, and exit for nodes.
function updateNodes() {
    var nodeSelection = container.selectAll("g.node")
        .data(nodes, function (d) { return d.id; });

    // Remove nodes that no longer exist.
    nodeSelection.exit().remove();

    // Create new nodes.
    var nodeEnter = nodeSelection.enter().append("g")
        .attr("class", "node")
        .on("contextmenu", function (event, d) {
            event.preventDefault();
            event.stopPropagation();
            hideTooltip();
            showContextMenu(event, d);
        })
        .on("dblclick", function (event, d) {
            event.stopPropagation();
            hideContextMenu();
            clearHighlight();
            if (d.expandable) {
                expandNode(d.id);
            }
        })
        .call(d3.drag()
            .filter(function (event) { return event.button === 0; })
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended))
        .on("mouseover", function (event, d) {
            if (contextMenuOpen) return;
            tooltipTimeout = setTimeout(function () {
                tooltip.transition().duration(TOOLTIP_SHOW_DURATION).style("opacity", 0.9);
                tooltip.html(getTooltipHTML(d))
                    .style("left", (event.pageX + 5) + "px")
                    .style("top", (event.pageY - 28) + "px");
            }, TOOLTIP_SHOW_DELAY);
        })
        .on("mouseout", function () {
            clearTimeout(tooltipTimeout);
            tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
        });

    // Append circle and text to new nodes.
    nodeEnter.append("circle")
        .attr("r", 10)
        .attr("class", function (d) {
            return d.expandable ? "node-expandable" : "node-default";
        });
    nodeEnter.append("text")
        .attr("x", 12)
        .attr("dy", ".35em")
        .text(function (d) { return d.id; });

    // Merge new nodes with existing ones.
    var allNodes = nodeEnter.merge(nodeSelection);
    // Refresh the CSS class for all nodes.
    allNodes.select("circle")
        .attr("class", function (d) {
            return d.expandable ? "node-expandable" : "node-default";
        });
}

// Update links selection: handles enter and exit for links.
function updateLinks(fullLinks) {
    var linkSelection = container.selectAll("line")
        .data(fullLinks, function (d) { return d.source.id + "-" + d.target.id; });

    linkSelection.exit().remove();

    linkSelection.enter()
        .insert("line", ":first-child")
        .attr("class", function (d) {
            return "edge edge-" + (d.relation_type || "unknown");
        })
        .on("mouseover", function (event, d) {
            if (contextMenuOpen) return;
            tooltipTimeout = setTimeout(function () {
                tooltip.transition().duration(TOOLTIP_SHOW_DURATION).style("opacity", 0.9);
                tooltip.html("Relation: " + (d.relation_type || "unknown"))
                    .style("left", (event.pageX + 5) + "px")
                    .style("top", (event.pageY - 28) + "px");
            }, TOOLTIP_SHOW_DELAY);
        })
        .on("mouseout", function () {
            clearTimeout(tooltipTimeout);
            tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
        });
}

function updateSimulation(fullLinks) {
    simulation.nodes(nodes).on("tick", function () {
        container.selectAll("line")
            .attr("x1", function (d) { return d.source.x; })
            .attr("y1", function (d) { return d.source.y; })
            .attr("x2", function (d) { return d.target.x; })
            .attr("y2", function (d) { return d.target.y; });
        container.selectAll("g.node")
            .attr("transform", function (d) { return "translate(" + d.x + "," + d.y + ")"; });
    });
    simulation.force("link").links(fullLinks);
    simulation.alphaTarget(0.2).restart();
    setTimeout(() => simulation.stop(), 10000);
}

function loadInitialGraph() {
    fetchJSON("/api/root")
        .then(data => {
            updateGraph(data.nodes, data.edges);
        })
        .catch(error => {
            // The error handling is already done in fetchJSON.
        });
}

function expandNode(nodeId) {
    // Call API with current displayed node IDs.
    fetchJSON(`/api/node/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(data => {
            // Immediately add all returned nodes to the displayed set.
            data.nodes.forEach(n => displayedRuleIDs.add(n.id));

            // Force the parent's state to non-expandable right away.
            const parentFromResponse = data.nodes.find(n => n.id === nodeId);
            if (parentFromResponse) {
                parentFromResponse.is_expanded = true;
                parentFromResponse.expandable = false;
            }

            // Update the graph with the API response.
            updateGraph(data.nodes, data.edges);
        })
        .catch(error => {
            // The error handling is already done in fetchJSON.
        });
}

function expandParents(nodeId) {
    fetchJSON(`/api/parents/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(data => {
            const targetNode = nodes.find(n => n.id === nodeId);
            if (targetNode) {
                targetNode.parents_expanded = true;
            }
            updateGraph(data.nodes, data.edges);
        })
        .catch(error => {
            // The error handling is already done in fetchJSON.
        });
}

function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.2).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
}

function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;

    let foundNode = nodes.find(n => n.id === searchInput);
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
        fetchJSON(`/api/node/${searchInput}?displayed=${getDisplayedIds()}`)
            .then(data => {
                foundNode = data.nodes.find(n => n.id === searchInput);
                if (foundNode) {
                    updateGraph(data.nodes, data.edges);
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
                // The error handling is already done in fetchJSON.
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

    // "Show children" menu item - initially disabled
    const showChildrenItem = contextMenu.append("div")
        .text("Show children")
        .style("padding", "5px")
        .style("cursor", "pointer")
        .style("opacity", 0.5)
        .style("pointer-events", "none")
        .on("click", () => {
            hideContextMenu();
            if (d.expandable) {
                expandNode(d.id);
            }
        });
    if (d.expandable) {
        fetchJSON(`/api/node/${d.id}?displayed=${getDisplayedIds()}`)
            .then(data => {
                let updatedState = data.nodes.find(n => n.id === d.id);
                d.expandable = updatedState.expandable;
                if (d.expandable) {
                    showChildrenItem.style("opacity", 1)
                        .style("pointer-events", "auto");
                } else {
                    showChildrenItem.style("opacity", 0.5)
                        .style("pointer-events", "none");
                }
            })
            .catch(error => {
                // The error handling is already done in fetchJSON.
            });
    }

    // "Show parents" menu item - initially disabled
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
        fetchJSON(`/api/parents/${d.id}?displayed=${getDisplayedIds()}`)
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
                // The error handling is already done in fetchJSON.
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
    if (event.code === "Space" || event.ctrlKey) {
        if (!simulationPausedByKey) {
            simulationPausedByKey = true;
            simulation.stop();
        }
    }
});

document.addEventListener("keyup", (event) => {
    if (simulationPausedByKey && (event.code === "Space" || !event.ctrlKey)) {
        simulationPausedByKey = false;
        simulation.alpha(1).restart();
    }
});

// Initial graph load
loadInitialGraph();

// ----- Legend Building Logic -----
function buildLegend() {
    const nodeLegendData = [
        { label: "Expandable Node", class: "node-expandable" },
        { label: "Default Node", class: "node-default" }
    ];

    const nodeLegend = svg.append("g")
        .attr("class", "legend node-legend")
        .attr("transform", "translate(20,20)");

    const nodeLegendItems = nodeLegend.selectAll(".legend-item")
        .data(nodeLegendData)
        .enter()
        .append("g")
        .attr("class", "legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    nodeLegendItems.append("circle")
        .attr("r", 8)
        .attr("class", d => d.class);

    nodeLegendItems.append("text")
        .attr("x", 15)
        .attr("y", 5)
        .text(d => d.label)
        .attr("fill", "#eee")
        .attr("font-size", "14px");

    const edgeLegendData = [
        { label: "if_sid", class: "edge-if_sid" },
        { label: "if_matched_sid", class: "edge-if_matched_sid" },
        { label: "if_group", class: "edge-if_group" },
        { label: "if_matched_group", class: "edge-if_matched_group" },
        { label: "No parent", class: "edge-no_parent" },
        { label: "Unknown", class: "edge-unknown" }
    ];

    const edgeLegend = svg.append("g")
        .attr("class", "legend edge-legend")
        .attr("transform", "translate(20,100)");

    const edgeLegendItems = edgeLegend.selectAll(".legend-item")
        .data(edgeLegendData)
        .enter()
        .append("g")
        .attr("class", "legend-item")
        .attr("transform", (d, i) => `translate(0, ${i * 25})`);

    edgeLegendItems.append("line")
        .attr("x1", 0)
        .attr("y1", 8)
        .attr("x2", 30)
        .attr("y2", 8)
        .attr("class", d => d.class)
        .attr("stroke-width", 4);

    edgeLegendItems.append("text")
        .attr("x", 40)
        .attr("y", 12)
        .text(d => d.label)
        .attr("fill", "#eee")
        .attr("font-size", "14px");
}

// Call buildLegend() after the graph loads.
buildLegend();
