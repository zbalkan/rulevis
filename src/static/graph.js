// =================================================================================
// 1. CONSTANTS & GLOBAL STATE
// =================================================================================

const STYLES = {
    nodes: { default: 'grey', expandable: 'steelblue', highlight: 'yellow', text: '#fff' },
    edges: { if_sid: 'blue', if_matched_sid: 'green', if_group: 'red', if_matched_group: 'purple', no_parent: '#6b6b6b', unknown: '#999' },
    legend: { text: '#eee' }
};

let nodes = [];
let links = [];
let nodeMap = new Map();
let highlightedNodeId = null;
let displayedRuleIDs = new Set();
let simulationPausedByKey = false;
let transform = d3.zoomIdentity;
let statsPanelOpen = false;
let heatmapModalOpen = false;

// =================================================================================
// 2. INITIALIZATION
// =================================================================================

const canvas = d3.select("canvas");
const context = canvas.node().getContext("2d");
const rect = canvas.node().getBoundingClientRect();
const width = rect.width;
const height = rect.height;
const devicePixelRatio = window.devicePixelRatio || 1;

canvas.attr('width', width * devicePixelRatio);
canvas.attr('height', height * devicePixelRatio);
context.scale(devicePixelRatio, devicePixelRatio);

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

// Initial graph load
resetGraph(true);


// =================================================================================
// 3. MAIN RENDER LOOP
// =================================================================================

function render() {
    context.save();
    context.clearRect(0, 0, width * devicePixelRatio, height * devicePixelRatio);
    context.translate(transform.x, transform.y);
    context.scale(transform.k, transform.k);

    // Draw Edges
    context.lineWidth = 1.5 / transform.k;
    links.forEach(link => {
        const edgeColor = STYLES.edges[link.relation_type] || STYLES.edges.unknown;
        context.beginPath();
        context.moveTo(link.source.x, link.source.y);
        context.lineTo(link.target.x, link.target.y);
        context.strokeStyle = edgeColor;
        context.stroke();
        context.fillStyle = edgeColor;
        drawArrowhead(link.source, link.target);
    });

    // Draw Nodes and Text
    const dynamicTextThreshold = 1.0;
    const textVisibilityThreshold = 0.4;
    const k = transform.k;

    nodes.forEach(node => {
        context.beginPath();
        context.arc(node.x, node.y, 10, 0, 2 * Math.PI);
        context.fillStyle = (node.expandable && !node.is_expanded) ? STYLES.nodes.expandable : STYLES.nodes.default;
        context.fill();

        if (node.id === highlightedNodeId) {
            context.strokeStyle = STYLES.nodes.highlight;
            context.lineWidth = 3 / transform.k;
            context.stroke();
        }

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

    // Draw UI Overlays
    buildLegend();
    drawCounter();
}


// =================================================================================
// 4. RENDERING HELPERS
// =================================================================================

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
    const legendX = 20, itemSpacing = 25, textOffset = 15;
    let legendY = 30;

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

function drawArrowhead(source, target) {
    const headLength = 6, nodeRadius = 10;
    const angle = Math.atan2(target.y - source.y, target.x - source.x);
    const tipX = target.x - nodeRadius * Math.cos(angle);
    const tipY = target.y - nodeRadius * Math.sin(angle);

    context.beginPath();
    context.moveTo(tipX, tipY);
    context.lineTo(tipX - headLength * Math.cos(angle - Math.PI / 6), tipY - headLength * Math.sin(angle - Math.PI / 6));
    context.lineTo(tipX - headLength * Math.cos(angle + Math.PI / 6), tipY - headLength * Math.sin(angle + Math.PI / 6));
    context.closePath();
    context.fill();
}

function drawCounter() {
    const counterText = `Nodes: ${nodes.length} | Edges: ${links.length}`;
    const xPos = 20, yPos = height - 20;
    context.font = "14px sans-serif";
    context.fillStyle = STYLES.legend.text;
    context.textAlign = "left";
    context.fillText(counterText, xPos, yPos);
}


// =================================================================================
// 5. USER ACTION HANDLERS
// =================================================================================

function handleSearch() {
    const searchInput = document.getElementById("searchBox").value.trim();
    if (!searchInput) return;
    clearHighlight();

    if (nodeMap.has(searchInput)) {
        highlightAndCenterNode(searchInput);
    } else {
        fetchJSON(`/api/nodes?mode=search&id=${searchInput}&displayed=${getDisplayedIds()}`)
            .then(data => {
                updateGraph(data.nodes, data.edges, () => {
                    highlightAndCenterNode(searchInput);
                });
            })
            .catch(error => { /* Errors handled by fetchJSON */ });
    }
}

function handleSearchById(ruleId) {
    if (statsPanelOpen) {
        hideStatsPanel();
    }
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

    canvas.transition().duration(750).call(zoom.transform, newTransform);
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


// =================================================================================
// 6. GRAPH DATA FUNCTIONS
// =================================================================================

function updateGraph(newNodesData, newLinksData, onUpdateComplete = null) {
    const newIds = new Set((newNodesData || []).map(n => n.id));

    (newNodesData || []).forEach(newNode => {
        if (!nodeMap.has(newNode.id)) {
            nodeMap.set(newNode.id, newNode);
            displayedRuleIDs.add(newNode.id);
        } else {
            Object.assign(nodeMap.get(newNode.id), newNode);
        }
    });
    nodes = Array.from(nodeMap.values());

    const linkSet = new Set(links.map(l => `${l.source.id}-${l.target.id}`));
    (newLinksData || []).forEach(newLink => {
        const linkId = `${newLink.source}-${newLink.target}`;
        if (!linkSet.has(linkId) && nodeMap.has(newLink.source) && nodeMap.has(newLink.target)) {
            links.push({ ...newLink, source: nodeMap.get(newLink.source), target: nodeMap.get(newLink.target) });
            linkSet.add(linkId);
        }
    });

    if (newIds.size > 0) {
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

    if (onUpdateComplete) {
        simulation.on("tick.callback", () => {
            onUpdateComplete();
            simulation.on("tick.callback", null);
        });
    }

    simulation.nodes(nodes);
    simulation.force("link").links(links);
    simulation.alpha(1).restart();
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

function expandNode(nodeId) {
    fetchJSON(`/api/nodes?id=${nodeId}&neighbors=children&displayed=${getDisplayedIds()}`)
        .then(data => {
            updateGraph(data.nodes, data.edges);
            const parentNode = nodeMap.get(nodeId);
            if (parentNode) {
                showDetailsPanel(parentNode);
            }
        });
}

function expandAllParents(nodeId, parentIdsString) {
    const parentIds = parentIdsString.split(',');
    const undisplayedParentIds = parentIds.filter(id => !displayedRuleIDs.has(id));

    if (undisplayedParentIds.length === 0) {
        showNotification("All parent nodes are already displayed.");
        return;
    }

    fetchJSON(`/api/nodes?ids=${undisplayedParentIds.join(',')}&displayed=${getDisplayedIds()}`)
        .then(data => {
            updateGraph(data.nodes, data.edges);
            const sourceNode = nodeMap.get(nodeId);
            if (sourceNode) {
                showDetailsPanel(sourceNode);
            }
        });
}


// =================================================================================
// 7. LOW-LEVEL & UTILITY HELPERS
// =================================================================================

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

function showNotification(message) {
    let toast = document.getElementById("toastNotification");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toastNotification";
        toast.style.cssText = `position: fixed; top: 120px; right: 40px; background: #800404; color: #eee; padding: 10px 15px; border-radius: 4px; z-index: 3000; opacity: 0; transition: opacity 0.5s ease;`;
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = 1;
    setTimeout(() => { toast.style.opacity = 0; }, 3000);
}

function showDetailsPanel(d) {
    const panel = document.getElementById("detailsPanel");
    const content = document.getElementById("detailsContent");
    content.innerHTML = `<h3>Details for Rule: ${d.id}</h3><p><i>Loading full details...</i></p>`;
    panel.classList.add("visible");

    fetchJSON(`/api/nodes?id=${d.id}&neighbors=both&include=details`)
        .then(details => {
            const hasUndisplayedParents = details.parents && details.parents.some(p => !displayedRuleIDs.has(p.id));
            const allParentIds = (details.parents || []).map(p => p.id).join(',');
            const parentExpandBtn = hasUndisplayedParents ? `<button class="expand-all-btn" onclick="expandAllParents('${d.id}', '${allParentIds}')">Expand All</button>` : '';
            const hasUndisplayedChildren = details.children && details.children.some(c => !displayedRuleIDs.has(c.id));
            const childExpandBtn = hasUndisplayedChildren ? `<button class="expand-all-btn" onclick="expandNode('${d.id}')">Expand All</button>` : '';
            const renderList = (items) => {
                if (!items || items.length === 0) return `<p>No related rules.</p>`;
                return `<ul>${items.map(item => {
                    const isDisplayed = displayedRuleIDs.has(item.id);
                    const clickAction = !isDisplayed ? `onclick="handleSearchById('${item.id}')"` : '';
                    const li_class = isDisplayed ? '' : 'class="not-displayed"';
                    return `<li ${li_class} ${clickAction}><strong>${item.relation_type}:</strong> ${item.id}</li>`;
                }).join('')}</ul>`;
            };
            const groupsList = (details.groups && details.groups.length > 0) ? `<ul>${details.groups.map(g => `<li>${g}</li>`).join('')}</ul>` : '<p>No groups assigned.</p>';
            content.innerHTML = `<h3>Details for Rule: ${details.id}</h3><p><strong>Description:</strong> ${details.description || 'N/A'}</p><div class="details-header"><h4>Parent Rules</h4>${parentExpandBtn}</div>${renderList(details.parents)}<div class="details-header"><h4>Child Rules</h4>${childExpandBtn}</div>${renderList(details.children)}<h4>Groups</h4>${groupsList}`;
        })
        .catch(error => {
            content.innerHTML = `<h3>Details for Rule: ${d.id}</h3><p style="color: red;">Could not load details.</p>`;
            console.error(`Error fetching details for ${d.id}:`, error);
        });
}

function hideDetailsPanel() {
    document.getElementById("detailsPanel").classList.remove("visible");
}

function showStatsPanel() {
    const panel = document.getElementById("statsPanel");
    const content = document.getElementById("statsContent");
    content.innerHTML = `<h3>Graph Statistics</h3><p><i>Loading...</i></p>`;
    panel.classList.add("visible");
    statsPanelOpen = true;

    fetchJSON('/api/stats')
        .then(stats => {
            const renderStatsList = (items, title) => {
                if (!items || items.length === 0) return `<h4>${title}</h4><p>No data.</p>`;
                let listHtml = `<h4>${title}</h4><ul>`;
                items.forEach(item => {
                    const isDisplayed = displayedRuleIDs.has(item.id);
                    const clickAction = `onclick="handleSearchById('${item.id}')"`;
                    const li_class = isDisplayed ? '' : 'class="not-displayed"';
                    let detail = '';
                    if (item.count !== undefined){ detail = `(${item.count})`;}
                    if (item.note !== undefined){ detail = `(${item.note})`;}
                    listHtml += `<li ${li_class} ${clickAction}><strong>${item.id}</strong> ${detail}</li>`;
                });
                listHtml += '</ul>';
                return listHtml;
            };

            content.innerHTML = `
                <h3>Graph Statistics</h3>
                ${renderStatsList(stats.top_direct_descendants, "Most Direct Children")}
                ${renderStatsList(stats.top_indirect_descendants, "Most Total Children (Highest Impact)")}
                ${renderStatsList(stats.top_direct_ancestors, "Most Direct Parents")}
                ${renderStatsList(stats.top_indirect_ancestors, "Most Total Parents (Complex Dependencies)")}
                ${renderStatsList(stats.isolated_rules, "Isolated Rules")}
            `;
        })
        .catch(error => {
            content.innerHTML = `<h3>Graph Statistics</h3><p style="color: red;">Could not load statistics.</p>`;
            console.error("Error fetching stats:", error);
        });
}

function hideStatsPanel() {
    document.getElementById("statsPanel").classList.remove("visible");
    statsPanelOpen = false;
}

function showHeatmap() {
    const modal = document.getElementById("heatmapModal");
    const content = document.getElementById("heatmapContent");
    content.innerHTML = '<p style="color: #eee; padding: 20px;">Loading Heatmap...</p>';
    modal.classList.add("visible");
    heatmapModalOpen = true;

    fetchJSON('/api/heatmap')
        .then(data => {
            renderHeatmap(data);
        })
        .catch(error => {
            content.innerHTML = '<p style="color: red; padding: 20px;">Could not load heatmap data.</p>';
        });
}

function hideHeatmap() {
    document.getElementById("heatmapModal").classList.remove("visible");
    heatmapModalOpen = false;
}

function renderHeatmap(data) {
    const content = d3.select("#heatmapContent");
    content.html(""); // Clear previous content

    const { width, height } = content.node().getBoundingClientRect();

    const svg = content.append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height]);

    const g = svg.append("g"); // Group for zooming

    const blocks = data.blocks;
    const metadata = data.metadata;

    // --- START: NEW RENDERING LOGIC ---

    // 1. Define the Color Scale
    // This scale maps a count to a color.
    // Domain: [0, 1, 2-5, 6-10, >10]
    // Range:  [gray, light-red, mid-red, bright-red, intense-red]
    const color = d3.scaleThreshold()
        .domain([1, 2, 6, 11]) // The upper bound of each range
        .range([
            "#444444", // 0 rules (unused)
            "#8B0000", // 1 rule (dark red)
            "#B22222", // 2-5 rules (firebrick)
            "#FF4500", // 6-10 rules (orangered)
            "#FF0000"  // >10 rules (pure red)
        ]);

    // 2. Calculate Grid Layout
    const margin = { top: 30, right: 20, bottom: 20, left: 20 };
    const gridSize = 12; // The size of each square in pixels
    const gridCols = Math.floor((width - margin.left - margin.right) / gridSize);
    const gridRows = Math.ceil(blocks.length / gridCols);

    // 3. Create the Grid
    const cells = g.selectAll("rect")
        .data(blocks)
        .join("rect")
            .attr("x", (d, i) => (i % gridCols) * gridSize + margin.left)
            .attr("y", (d, i) => Math.floor(i / gridCols) * gridSize + margin.top)
            .attr("width", gridSize - 1) // -1 for a small gap
            .attr("height", gridSize - 1)
            .attr("fill", d => color(d.count))
            .style("cursor", "pointer")
            .on("click", (event, d) => {
                // When a block is clicked, search for the first rule in that range
                const firstRuleId = d.id.split('-')[0];
                hideHeatmap();
                handleSearchById(firstRuleId);
            });

    // 4. Add Tooltips
    cells.append("title")
        .text(d => `Rule Range: ${d.id}\nUsed IDs: ${d.count}`);

    // 5. Add a Title
    g.append("text")
        .attr("x", width / 2)
        .attr("y", 20)
        .attr("text-anchor", "middle")
        .style("font-size", "16px")
        .style("fill", "#eee")
        .text(`Rule ID Occupancy (Block Size: ${metadata.block_size})`);

    // --- END: NEW RENDERING LOGIC ---

    // Add zoom behavior to the SVG
    const zoom = d3.zoom()
        .scaleExtent([1, 8])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
        });
    
    svg.call(zoom);
}

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
        if (error.isHandled) { throw error; }
        showNotification("Server not reachable. Please check connection.");
        throw error;
    }
}


// =================================================================================
// 8. EVENT LISTENER BINDINGS
// =================================================================================

// --- UI Buttons and Inputs ---
document.getElementById("resetZoom").addEventListener("click", () => handleSearchById('0'));
document.getElementById("resetGraph").addEventListener("click", () => resetGraph(true));
document.getElementById("searchBtn").addEventListener("click", handleSearch);
document.getElementById("searchBox").addEventListener("keyup", e => { if (e.key === "Enter") handleSearch(); });
document.getElementById("detailsCloseBtn").addEventListener("click", clearHighlight);
document.getElementById("showStatsBtn").addEventListener("click", showStatsPanel);
document.getElementById("statsCloseBtn").addEventListener("click", hideStatsPanel);
// --- Keyboard Shortcuts ---
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        if (heatmapModalOpen) {
            event.preventDefault();
            hideHeatmap();
        } else if (highlightedNodeId) {
            event.preventDefault();
            clearHighlight();
        } else if (statsPanelOpen) {
            event.preventDefault();
            hideStatsPanel();
        }
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
document.getElementById("showHeatmapBtn").addEventListener("click", showHeatmap);
document.getElementById("heatmapCloseBtn").addEventListener("click", hideHeatmap);
// --- Canvas Interactions ---
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
