// --- Global State ---
let nodes = [];
let links = [];

// Global set to track displayed rule IDs
let displayedRuleIDs = new Set();

// Flag to indicate if the context menu is open (freeze state)
let contextMenuOpen = false;

// Flag to indicate if simulation is paused via keyboard
let simulationPausedByKey = false;

let tooltipTimeout;
const TOOLTIP_SHOW_DELAY = 500;
const TOOLTIP_HIDE_DURATION = 300;
const TOOLTIP_SHOW_DURATION = 200;

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
                updateCounter();
            }
            // update graph with the first-level nodes and edges.
            updateGraph(data.nodes, data.edges);
            // Reposition nodes to near the virtual root (with slight spread).
            resetToRootPositions();
            // After a short delay, release pins and restart simulation.
            releaseNodePins();
            simulation.alpha(0.1).alphaDecay(0.2).restart();
        })
        .catch(error => {
            console.error("Error during reposition:", error);
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

const width = window.innerWidth;
const height = window.innerHeight * 0.9;

const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-80))
    .force("center", d3.forceCenter(width / 2, height / 2))
    // .force("radial", d3.forceRadial(150, width / 2, height / 2).strength(0.15))
    .velocityDecay(0.4)
    .alphaDecay(0.5);


// Helper function to hide tooltip
function hideTooltip() {
    clearTimeout(tooltipTimeout);
    tooltip.transition().duration(TOOLTIP_HIDE_DURATION).style("opacity", 0);
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
    const newIds = (newNodes || []).map(n => n.id).filter(id => !displayedRuleIDs.has(id));

    const nodeMap = mergeNodes(newNodes);

    mergeLinks(newLinks);

    // This now runs *after* data is merged, so `displayedRuleIDs` is up-to-date.
    if (newIds.length > 0) {
        linkUpExistingNodes();
    }

     // After all data is merged, check every node to see if it should be considered "expanded".
    nodes.forEach(node => {
        const all_children_ids = node.children_ids || [];

        if (all_children_ids.length === 0) {
            // If the node has no children, it can't be expanded.
            node.expandable = false;
            node.is_expanded = true; // Mark leaf nodes as "expanded" for consistent styling.
        } else {
            // Check if EVERY child from the complete list is currently on screen.
            const allChildrenAreVisible = all_children_ids.every(childId => displayedRuleIDs.has(childId));

            if (allChildrenAreVisible) {
                // All possible children are on screen. This node is fully expanded.
                node.expandable = false;
                node.is_expanded = true;
            } else {
                // Some children are still hidden. This node is still expandable.
                node.expandable = true;
                node.is_expanded = false;
            }
        }
    });

    // --- D3 VISUALIZATION BINDING ---
    const nodeSelection = container.selectAll("g.node").data(nodes, d => d.id);
    nodeSelection.exit().remove();

    const nodeEnter = nodeSelection.enter().append("g")
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
            if (d.expandable) expandNode(d.id);
        })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended))
        .on("mouseover", function (event, d) {
            if (contextMenuOpen) return;
            tooltipTimeout = setTimeout(() => {
                tooltip.transition().duration(TOOLTIP_SHOW_DURATION).style("opacity", 0.9);
                tooltip.html(getTooltipHTML(d))
                    .style("left", (event.pageX + 5) + "px")
                    .style("top", (event.pageY - 28) + "px");
            }, TOOLTIP_SHOW_DELAY);
        })
        .on("mouseout", function () {
            hideTooltip();
        });

    nodeEnter.append("circle").attr("r", 10);
    nodeEnter.append("text")
        .attr("x", 12)
        .attr("dy", ".35em")
        .text(d => d.id);

    nodeEnter.merge(nodeSelection)
        .select("circle")
        .attr("class", d => {
            // If the node has been expanded OR it was never expandable, it's a "default" node (grey).
            // Otherwise, it's an "expandable" node (blue).
            if (d.is_expanded || !d.expandable) {
                return "node-default";
            } else {
                return "node-expandable";
            }
        });

    const fullLinks = links.map(l => ({ ...l, source: nodeMap.get(l.source), target: nodeMap.get(l.target) })).filter(l => l.source && l.target);
    const linkSelection = container.selectAll("line").data(fullLinks, d => `${d.source.id}-${d.target.id}`);
    linkSelection.exit().remove();
    linkSelection.enter().insert("line", ":first-child").attr("class", d => `edge edge-${d.relation_type || "unknown"}`);

    // --- SIMULATION UPDATE ---
    simulation.nodes(nodes).on("tick", () => {
        container.selectAll("line").attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        container.selectAll("g.node").attr("transform", d => `translate(${d.x},${d.y})`);
    });
    simulation.force("link").links(fullLinks);
    simulation.alphaTarget(0.5).restart();
    if (window.stopTimeout) clearTimeout(window.stopTimeout);
    window.stopTimeout = setTimeout(() => {
        simulation.alphaTarget(0.5); // Set the target to 0, allowing it to cool and stop.
    }, 5000); // Let it run for at least 5 seconds before it's allowed to stop.

    updateCounter();
}

function mergeLinks(newLinks) {
    (newLinks || []).forEach(newLink => {
        if (!links.some(l => l.source === newLink.source && l.target === newLink.target)) {
            links.push(newLink);
        }
    });
}

function mergeNodes(newNodes) {
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    (newNodes || []).forEach(newNode => {
        const existingNode = nodeMap.get(newNode.id);
        if (existingNode) {
            // Node already exists. Preserve its core properties (position, velocity)
            // and merge the new properties (like 'expandable' or 'is_expanded') onto it.
            Object.assign(existingNode, newNode);
        } else {
            // This is a brand new node. Add it to the map.
            nodeMap.set(newNode.id, newNode);
            displayedRuleIDs.add(newNode.id);
        }
    });
    nodes = Array.from(nodeMap.values());
    return nodeMap;
}

function linkUpExistingNodes() {
    const allDisplayed = Array.from(displayedRuleIDs);

    fetchJSON('/api/connections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: allDisplayed }),
    })
    .then(data => {
        const newLinks = data.edges || [];

        // Only call updateGraph if there are genuinely new links to add.
        const newLinksToAdd = newLinks.filter(newLink =>
            !links.some(l => l.source === newLink.source && l.target === newLink.target)
        );

        if (newLinksToAdd.length > 0) {
            // Call the main updateGraph function. It will handle merging the new links.
            // We pass an empty array for nodes because we are only adding links.
            updateGraph([], newLinksToAdd);
        }
    })
    .catch(error => {
        console.error("Error linking up existing nodes:", error);
    });
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
    fetchJSON(`/api/node/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(data => {
            const parentNode = data.nodes.find(n => n.id === nodeId);
            if (parentNode) {
                parentNode.is_expanded = true;
                parentNode.expandable = false; // The server should do this, but we can enforce it.
            }
            updateGraph(data.nodes, data.edges);
        })
        .catch(error => {
            console.error(`Error expanding node ${nodeId}:`, error);
        });
}

function expandParents(nodeId) {
    fetchJSON(`/api/parents/${nodeId}?displayed=${getDisplayedIds()}`)
        .then(data => {
            // Mark the node as having its parents expanded to prevent re-fetching.
            const targetNode = data.nodes.find(n => n.id === nodeId);
            if (targetNode) targetNode.parents_expanded = true;

            updateGraph(data.nodes, data.edges);
        })
        .catch(error => {
            console.error(`Error expanding parents for ${nodeId}:`, error);
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
    // The `event` object is passed directly to the function in D3 v7.
    // We check `event.active` to see if a simulation "tick" is still running from the drag.
    if (!event.active) {
        simulation.alphaTarget(0);
    }

    // If the simulation is NOT paused by the user's keypress, release the node's pin.
    if (!simulationPausedByKey) {
        d.fx = null;
        d.fy = null;
    }
}

function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;

    clearHighlight();

    const foundNode = nodes.find(n => n.id === searchInput);

    if (foundNode) {
        // CASE 1: Node is already on screen. Just highlight and center.
        highlightAndCenterNode(searchInput);
    } else {
        // CASE 2: Node is NOT on screen. Fetch it and its parent relationships.
        fetchJSON(`/api/parents/${searchInput}?displayed=${getDisplayedIds()}`)
            .then(data => {
                const searchedNodeData = data.nodes.find(n => n.id === searchInput);

                if (searchedNodeData) {
                    // --- INTELLIGENT PROCESSING LOGIC ---

                    // 1. Prepare the new node to be added.
                    const newNodesToAdd = [searchedNodeData];

                    // 2. Prepare a list for edges that we will conditionally add.
                    const newLinksToAdd = [];

                    // 3. Iterate through the edges returned by the API.
                    data.edges.forEach(edge => {
                        // An edge from this API is always { source: PARENT, target: CHILD }.
                        // We only care about edges pointing TO our searched node.
                        if (edge.target === searchInput) {
                            const parentId = edge.source;
                            // 4. CRUCIAL CHECK: Is the parent already on screen?
                            if (displayedRuleIDs.has(parentId)) {
                                // Yes, so we will add this edge.
                                newLinksToAdd.push(edge);
                            }
                        }
                    });

                    // 5. Update the graph with ONLY the searched node and the valid edges.
                    updateGraph(newNodesToAdd, newLinksToAdd);

                    // 6. Allow D3 to render, then highlight and center the new node.
                    setTimeout(() => {
                        highlightAndCenterNode(searchInput);
                    }, 100);

                } else {
                    showNotification("Node not found: " + searchInput);
                }
            })
            .catch(error => {
                // Error is handled by fetchJSON.
            });
    }
}

// The highlightAndCenterNode helper function from the previous step remains the same.
function highlightAndCenterNode(nodeId) {
    const nodeToHighlight = nodes.find(n => n.id === nodeId);
    if (!nodeToHighlight) return;

    container.selectAll("g.node")
        .filter(d => d.id === nodeId)
        .classed("highlight", true);

    simulation.stop();

    if (nodeToHighlight.x != null && nodeToHighlight.y != null) {
        const currentTransform = d3.zoomTransform(svg.node());
        const newTransform = d3.zoomIdentity
            .translate(width / 2, height / 2)
            .scale(currentTransform.k)
            .translate(-nodeToHighlight.x, -nodeToHighlight.y);

        svg.transition().duration(750).call(zoom.transform, newTransform);
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
    if (!simulationPausedByKey && !contextMenuOpen) {
        simulation.restart();
    }
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


document.addEventListener("keydown", (event) => {
    // Use `event.key` for modern browsers, and check for spacebar or Ctrl.
    if ((event.key === " " || event.key === "Control") && !simulationPausedByKey) {
        event.preventDefault(); // Prevents spacebar from scrolling the page
        simulationPausedByKey = true;
        simulation.stop();
    }
});

document.addEventListener("keyup", (event) => {
    // Check if the key that was released is the one we are tracking.
    if (simulationPausedByKey && (event.key === " " || event.key === "Control")) {
        simulationPausedByKey = false;
        // Only release the node pins if the user is not currently dragging.
        if (!d3.event.active) {
             releaseNodePins();
             simulation.alpha(1).restart();
        }
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
