// --- Global State ---
let nodes = [];
let links = [];
let nodeMap = new Map();
let highlightedNodeId = null;

// Global set to track displayed rule IDs
let displayedRuleIDs = new Set();

// Flag to indicate if simulation is paused via keyboard
let simulationPausedByKey = false;

const STYLES = {
    nodes: {
        default: 'grey',
        expandable: 'steelblue',
        highlight: 'yellow',
        text: '#fff'
    },
    edges: {
        if_sid: 'blue',
        if_matched_sid: 'green',
        if_group: 'red',
        if_matched_group: 'purple',
        no_parent: '#6b6b6b',
        unknown: '#999' // Default edge color
    },
    legend: {
        text: '#eee'
    }
};

// --- Toast Notification ---
function showNotification(message) {
    let toast = document.getElementById("toastNotification");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toastNotification";
        toast.style.cssText = `
            position: fixed; top: 120px; right: 40px; background: #800404; color: #eee;
            padding: 10px 15px; border-radius: 4px; z-index: 3000; opacity: 0;
            transition: opacity 0.5s ease;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = 1;
    setTimeout(() => { toast.style.opacity = 0; }, 3000);
}

// --- Details Panel Logic ---
function showDetailsPanel(d) {
    const panel = document.getElementById("detailsPanel");
    const content = document.getElementById("detailsContent");
    content.innerHTML = `<h3>Details for Rule: ${d.id}</h3><p><i>Loading full details...</i></p>`;
    panel.classList.add("visible");

    fetchJSON(`/api/nodes?id=${d.id}&neighbors=both&include=details`)
        .then(details => {
            const hasUndisplayedParents = details.parents && details.parents.some(p => !displayedRuleIDs.has(p.id));
            const allParentIds = (details.parents || []).map(p => p.id).join(',');
            const parentExpandBtn = hasUndisplayedParents
                ? `<button class="expand-all-btn" onclick="expandAllParents('${d.id}', '${allParentIds}')">Expand All</button>`
                : '';

            const hasUndisplayedChildren = details.children && details.children.some(c => !displayedRuleIDs.has(c.id));
            const childExpandBtn = hasUndisplayedChildren
                ? `<button class="expand-all-btn" onclick="expandNode('${d.id}')">Expand All</button>`
                : '';
    
            const renderList = (items, type) => {
                if (!items || items.length === 0) return `<p>No ${type}.</p>`;
                return `<ul>${items.map(item => {
                    const isDisplayed = displayedRuleIDs.has(item.id);
                    const clickAction = !isDisplayed ? `onclick="handleSearchById('${item.id}')"` : '';
                    const li_class = isDisplayed ? '' : 'class="not-displayed"';
                    return `<li ${li_class} ${clickAction}><strong>${item.relation_type}:</strong> ${item.id}</li>`;
                }).join('')}</ul>`;
            };
            const groupsList = (details.groups && details.groups.length > 0)
                ? `<ul>${details.groups.map(g => `<li>${g}</li>`).join('')}</ul>`
                : '<p>No groups assigned.</p>';

            content.innerHTML = `
                <h3>Details for Rule: ${details.id}</h3>
                <p><strong>Description:</strong> ${details.description || 'N/A'}</p>
                
                <div class="details-header">
                    <h4>Parent Rules</h4>
                    ${parentExpandBtn}
                </div>
                ${renderList(details.parents, 'parents')}
                
                <div class="details-header">
                    <h4>Child Rules</h4>
                    ${childExpandBtn}
                </div>
                ${renderList(details.children, 'children')}

                <h4>Groups</h4>${groupsList}
            `;
        })
        .catch(error => {
            content.innerHTML = `<h3>Details for Rule: ${d.id}</h3><p style="color: red;">Could not load details.</p>`;
            console.error(`Error fetching details for ${d.id}:`, error);
        });
}

function hideDetailsPanel() {
    document.getElementById("detailsPanel").classList.remove("visible");
}

// --- API Fetch Wrapper ---
async function fetchJSON(url, options = {}) {
    try {
        const response = await fetch(url, options);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const message = errorData.error || `Error: ${response.status} ${response.statusText}`;
            
            showNotification(message);
            
            const httpError = new Error(message );
            httpError.isHandled = true;
            throw httpError;
        }

        return await response.json( );

    } catch (error) {
        if (error.isHandled) {
            throw error;
        }

        showNotification("Server not reachable. Please check connection.");

        throw error;
    }
}

// --- Canvas and D3 Setup ---
const canvas = d3.select("canvas");
const context = canvas.node().getContext("2d");
const width = window.innerWidth;
const height = window.innerHeight * 0.8;

const devicePixelRatio = window.devicePixelRatio || 1;
canvas.attr('width', width * devicePixelRatio);
canvas.attr('height', height * devicePixelRatio);
canvas.style('width', `${width}px`);
canvas.style('height', `${height}px`);
context.scale(devicePixelRatio, devicePixelRatio);

let transform = d3.zoomIdentity;

const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-120))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .on("tick", render);

const zoom = d3.zoom()
    .scaleExtent([0.02, 5])
    .on("zoom", (event) => {
        transform = event.transform;
        render();
    });

canvas.call(zoom);

// --- Graph Data Management ---
function updateGraph(newNodesData, newLinksData, onUpdateComplete = null) {
    const newIds = new Set((newNodesData || []).map(n => n.id));

    // Merge nodes
    (newNodesData || []).forEach(newNode => {
        if (!nodeMap.has(newNode.id)) {
            nodeMap.set(newNode.id, newNode);
            displayedRuleIDs.add(newNode.id);
        } else {
            Object.assign(nodeMap.get(newNode.id), newNode);
        }
    });
    nodes = Array.from(nodeMap.values());

    // Merge links
    const linkSet = new Set(links.map(l => `${l.source.id}-${l.target.id}`));
    (newLinksData || []).forEach(newLink => {
        const linkId = `${newLink.source}-${newLink.target}`;
        if (!linkSet.has(linkId) && nodeMap.has(newLink.source) && nodeMap.has(newLink.target)) {
            links.push({
                ...newLink,
                source: nodeMap.get(newLink.source),
                target: nodeMap.get(newLink.target)
            });
            linkSet.add(linkId);
        }
    });

    // If new nodes were added, check for connections between existing nodes
    if (newIds.size > 0) {
        // This call to updateGraph will now work because the third argument will default to null.
        linkUpExistingNodes();
    }

     nodes.forEach(node => {
        const childrenIds = node.children_ids || [];
        
        if (childrenIds.length === 0) {
            node.expandable = false;
            node.is_expanded = true;
        } else {
            const allChildrenAreVisible = childrenIds.every(childId => displayedRuleIDs.has(childId));
            
            node.expandable = !allChildrenAreVisible;
            node.is_expanded = allChildrenAreVisible;
        }
    });

    // If a callback function is provided, set it up to run after the next tick.
    if (onUpdateComplete) {
        simulation.on("tick.callback", () => {
            // Run the callback
            onUpdateComplete();
            // IMPORTANT: Remove the callback listener so it only runs once.
            simulation.on("tick.callback", null);
        });
    }

    // Update simulation
    simulation.nodes(nodes);
    simulation.force("link").links(links);
    simulation.alpha(1).restart();

    updateCounter();
}

function linkUpExistingNodes() {
    fetchJSON('/api/edges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: Array.from(displayedRuleIDs) }),
    })
    .then(data => {
        if (data.edges && data.edges.length > 0) {
            updateGraph([], data.edges);
        }
    });
}

function buildLegend() {
    const nodeLegendData = [
        { label: "Expandable Node", color: STYLES.nodes.expandable },
        { label: "Default Node", color: STYLES.nodes.default }
    ];

    const edgeLegendData = [
        { label: "if_sid", color: STYLES.edges.if_sid },
        { label: "if_matched_sid", color: STYLES.edges.if_matched_sid },
        { label: "if_group", color: STYLES.edges.if_group },
        { label: "if_matched_group", color: STYLES.edges.if_matched_group },
        { label: "No parent", color: STYLES.edges.no_parent },
        { label: "Unknown", color: STYLES.edges.unknown }
    ];

    const legendX = 20;
    let legendY = 30;
    const itemSpacing = 25;
    const textOffset = 15;

    context.font = "14px sans-serif";
    context.fillStyle = STYLES.legend.text;

    nodeLegendData.forEach(item => {
        context.beginPath();
        context.arc(legendX, legendY, 8, 0, 2 * Math.PI);
        context.fillStyle = item.color;
        context.fill();
        context.fillStyle = STYLES.legend.text;
        context.fillText(item.label, legendX + textOffset, legendY + 5);
        legendY += itemSpacing;
    });

    legendY += 20;

    edgeLegendData.forEach(item => {
        context.beginPath();
        context.moveTo(legendX - 10, legendY);
        context.lineTo(legendX + 20, legendY);
        context.strokeStyle = item.color;
        context.lineWidth = 4;
        context.stroke();
        context.fillText(item.label, legendX + textOffset + 15, legendY + 5);
        legendY += itemSpacing;
    });
}

function render() {
    context.save();
    context.clearRect(0, 0, width * devicePixelRatio, height * devicePixelRatio);
    context.translate(transform.x, transform.y);
    context.scale(transform.k, transform.k);

    context.lineWidth = 1.5 / transform.k;
    links.forEach(link => {
        context.beginPath();
        context.moveTo(link.source.x, link.source.y);
        context.lineTo(link.target.x, link.target.y);
        context.strokeStyle = STYLES.edges[link.relation_type] || STYLES.edges.unknown;
        context.stroke();
    });

    const dynamicTextThreshold = 1.0;  // Above this, text size is dynamic.
    const textVisibilityThreshold = 0.4; // Below this, text is hidden.

    nodes.forEach(node => {
        context.beginPath();
        context.arc(node.x, node.y, 10, 0, 2 * Math.PI);
        const nodeColor = (node.expandable && !node.is_expanded) ? STYLES.nodes.expandable : STYLES.nodes.default;
        context.fillStyle = nodeColor;
        context.fill();

        if (node.id === highlightedNodeId) {
            context.strokeStyle = STYLES.nodes.highlight;
            context.lineWidth = 3 / transform.k;
            context.stroke();
        }

        const k = transform.k;
        if (k >= dynamicTextThreshold) {
            context.fillStyle = STYLES.nodes.text;
            context.font = `${12 / k}px sans-serif`;
            context.fillText(node.id, node.x + 15, node.y + 4);

        } else if (k >= textVisibilityThreshold) {
            context.fillStyle = STYLES.nodes.text;
            context.font = `10px sans-serif`;
            context.fillText(node.id, node.x + 15, node.y + 4);
        }
    });

    context.restore();
    buildLegend();
}

function findNodeAt(x, y) {
    const [ix, iy] = transform.invert([x, y]);
    const radiusSq = 100 / (transform.k * transform.k);
    for (let i = nodes.length - 1; i >= 0; i--) {
        const node = nodes[i];
        const dx = ix - node.x;
        const dy = iy - node.y;
        if (dx * dx + dy * dy < radiusSq) return node;
    }
    return null;
}

function getDisplayedIds() {
    return Array.from(displayedRuleIDs).join(",");
}

function expandNode(nodeId) {
    
    fetchJSON(`/api/nodes?id=${nodeId}&neighbors=children&displayed=${getDisplayedIds()}`)
        .then(data =>
        {
            updateGraph(data.nodes, data.edges);
            const parentNode = nodeMap.get(nodeId);
            if (parentNode) {
                showDetailsPanel(parentNode);
            }
        });
}

function expandAllParents(nodeId, parentIdsString) {
    const parentIds = parentIdsString.split(',');
    
    // Filter out any parents that are already on the screen.
    const undisplayedParentIds = parentIds.filter(id => !displayedRuleIDs.has(id));

    if (undisplayedParentIds.length === 0) {
        showNotification("All parent nodes are already displayed.");
        return;
    }

    fetchJSON(`/api/nodes?ids=${undisplayedParentIds}&neighbors=children&displayed=${getDisplayedIds()}`)
    .then(data => {
        // Update the graph with the new nodes and edges.
        updateGraph(data.nodes, data.edges);

        // Re-render the details panel to show the updated state.
        const sourceNode = nodeMap.get(nodeId);
        if (sourceNode) {
            showDetailsPanel(sourceNode);
        }
    });
}

function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;
    clearHighlight();

    if (nodeMap.has(searchInput)) {
        highlightAndCenterNode(searchInput);
    } else {
        fetchJSON(`/api/nodes?mode=search&id=${searchInput}&displayed=${getDisplayedIds()}`)
            .then(data => {
                // Pass a callback function to updateGraph.
                // This function will be executed only after the simulation
                // has calculated the new node's initial position.
                updateGraph(data.nodes, data.edges, () => {
                    highlightAndCenterNode(searchInput);
                });
            })
            .catch(error => {
                // Errors are handled by fetchJSON.
            });
    }
}

function handleSearchById(ruleId) {
    document.getElementById("searchBox").value = ruleId;
    handleSearch();
}

function highlightAndCenterNode(nodeId) {
    const node = nodeMap.get(nodeId);
    if (!node) return;

    if (node.x === undefined || node.y === undefined) {
        console.warn("Node has no position yet. Cannot center.");
        highlightedNodeId = nodeId;
        showDetailsPanel(node);
        render();
        return;
    }

    highlightedNodeId = nodeId;
    showDetailsPanel(node);
    render();

    node.fx = node.x;
    node.fy = node.y;

    const comfortableZoomLevel = 1.2;
    const targetScale = Math.max(transform.k, comfortableZoomLevel);

    const newTransform = d3.zoomIdentity
        .translate(width / 2, height / 2)
        .scale(targetScale)
        .translate(-node.x, -node.y);

    canvas.transition()
        .duration(750)
        .call(zoom.transform, newTransform);
}

function clearHighlight() {
    if (highlightedNodeId && nodeMap.has(highlightedNodeId)) {
        const highlightedNode = nodeMap.get(highlightedNodeId);
        highlightedNode.fx = null;
        highlightedNode.fy = null;
    }

    highlightedNodeId = null;
    hideDetailsPanel();
    render();

    if (!simulationPausedByKey) {
        simulation.alpha(0.3).restart();
    }
}

function resetGraph(fullReset) {
    if (fullReset) {
        nodes = [];
        links = [];
        nodeMap.clear();
        displayedRuleIDs.clear();
    }
    fetchJSON("/api/nodes?mode=root").then(data => {
        updateGraph(data.nodes, data.edges);
        canvas.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
    });
}

document.getElementById("resetZoom").addEventListener("click", () => handleSearchById(0));
document.getElementById("resetGraph").addEventListener("click", () => resetGraph(true));
document.getElementById("searchBtn").addEventListener("click", handleSearch);
document.getElementById("searchBox").addEventListener("keyup", e => e.key === "Enter" && handleSearch());
document.getElementById("detailsCloseBtn").addEventListener("click", clearHighlight);
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && highlightedNodeId) {
        event.preventDefault();
        clearHighlight();
        return;
    }
    if (event.key === " " && document.activeElement !== document.getElementById('searchBox')) {
        event.preventDefault();

        if (!simulationPausedByKey) {
            simulationPausedByKey = true;
            simulation.stop();
            showNotification("Simulation paused");
        }
    }
});

document.addEventListener("keyup", (event) => {
    if (event.key === " " && simulationPausedByKey) {
        simulationPausedByKey = false;
        
        simulation.alpha(0.3).restart();
        showNotification("Simulation resumed");
    }
});

document.addEventListener("contextmenu", (event) => {
    event.preventDefault();
});

canvas.on("click", (event) => {
    const node = findNodeAt(event.offsetX, event.offsetY);
    if (node) {
        highlightedNodeId = node.id;
        showDetailsPanel(node);
        render();
    } else {
        clearHighlight();
    }
});

canvas.call(d3.drag()
    .container(canvas.node())
    .subject((event) => findNodeAt(event.x, event.y))
    .on("start", (event) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
    })
    .on("drag", (event) => {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
    })
    .on("end", (event) => {
        if (!event.active) simulation.alphaTarget(0);
        if (!simulationPausedByKey) {
            event.subject.fx = null;
            event.subject.fy = null;
        }
    })
);

function updateCounter() {
    let counterDiv = document.getElementById("counter");
    if (!counterDiv) {
        counterDiv = document.createElement("div");
        counterDiv.id = "counter";
        counterDiv.style.cssText = `
            position: fixed; left: 10px; bottom: 10px; background: rgba(0,0,0,0.6);
            color: #eee; padding: 5px 10px; border-radius: 4px; font-family: sans-serif;
        `;
        document.body.appendChild(counterDiv);
    }
    counterDiv.textContent = `Nodes: ${nodes.length} | Edges: ${links.length}`;
}

resetGraph(true);