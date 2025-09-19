// =================================================================================
// 1. CONSTANTS & STYLES (FOR CANVAS RENDERING)
// =================================================================================

const STYLES = {
    nodes: { 
        default: 'grey', 
        expandable: 'steelblue', 
        highlight: 'yellow', 
        text: '#fff',
        collapsed: '#333'
    },
    edges: { 
        if_sid: 'blue', 
        if_matched_sid: 'green', 
        if_group: 'red', 
        if_matched_group: 'purple', 
        no_parent: '#6b6b6b', 
        unknown: '#999' 
    },
    legend: { text: '#eee' }
};

// =================================================================================
// 2. COMPONENT CLASSES (Self-Contained UI Managers)
// =================================================================================

class NotificationManager {
    constructor() {
        this.toastElement = null;
        this.timeoutId = null;
    }
    show(message) {
        if (this.timeoutId) clearTimeout(this.timeoutId);
        if (!this.toastElement) {
            this.toastElement = document.createElement("div");
            this.toastElement.id = "toastNotification";
            document.body.appendChild(this.toastElement);
        }
        this.toastElement.textContent = message;
        this.toastElement.classList.add("show");
        this.timeoutId = setTimeout(() => this.hide(), 3000);
    }
    hide() {
        if (this.toastElement) {
            this.toastElement.classList.remove("show");
        }
    }
}

class DetailsPanel {
    constructor(visualizer) {
        this.visualizer = visualizer;
        this.panel = document.getElementById("detailsPanel");
        this.content = document.getElementById("detailsContent");
        document.getElementById("detailsCloseBtn").addEventListener("click", () => this.visualizer.clearHighlight());
    }
    show(node) {
        this.content.innerHTML = `<h3>Details for Rule: ${node.id}</h3><p><i>Loading full details...</i></p>`;
        this.panel.classList.add("visible");
        fetchJSON(`/api/nodes?id=${node.id}&neighbors=both&include=details`)
        .then(details => this.render(details))
        .catch(error => {
            this.content.innerHTML = `<h3>Details for Rule: ${node.id}</h3><p style="color: #ff8a8a;">Could not load details.</p>`;
        });
    }
    hide() {
        this.panel.classList.remove("visible");
    }
    render(details) {
        const parentExpandBtn = details.parents && details.parents.some(p => !this.visualizer.displayedRuleIDs.has(p.id)) ? `<button class="expand-all-btn" onclick="window.visualizer.expandAllParents('${details.id}', '${(details.parents || []).map(p => p.id).join(',')}')">Expand All</button>` : '';
        const childExpandBtn = details.children && details.children.some(c => !this.visualizer.displayedRuleIDs.has(c.id)) ? `<button class="expand-all-btn" onclick="window.visualizer.expandNode('${details.id}')">Expand All</button>` : '';
        const renderList = (items) => !items || items.length === 0 ? `<p>No related rules.</p>` : `<ul>${items.map(item => `<li class="${this.visualizer.displayedRuleIDs.has(item.id) ? 'displayed' : 'not-displayed'}" onclick="window.visualizer.handleSearchById('${item.id}')"><strong>${item.relation_type}:</strong> ${item.id}</li>`).join('')}</ul>`;

        // --- Logic to derive and format the new fields ---
        const ruleLevel = parseInt(details.level, 10);
        const generatesAlert = ruleLevel >= 3;
        const alertClass = generatesAlert ? 'alert-true' : 'alert-false';

        const levelInfo = details.level ? `
            <div class="details-meta">
                <strong>Level:</strong>
                <span>${details.level}</span>
            </div>
        ` : '';

        const alertInfo = details.level ? `
            <div class="details-meta">
                <strong>Alert:</strong>
                <span class="${alertClass}">${generatesAlert}</span>
            </div>
        ` : '';
        
        const fileInfo = details.file ? `
            <div class="details-meta-full">
                <strong>File:</strong>
                <span>${details.file}</span>
            </div>
        ` : '';

        // --- Final HTML structure with the typo corrected ---
        this.content.innerHTML = `
            <h3>Details for Rule: ${details.id}</h3>
            
            <div class="info-box">
                <div class="info-box-row">
                    ${levelInfo}
                    ${alertInfo}
                </div>
                <div class="info-box-row">
                    ${fileInfo}
                </div>
            </div>

            <p><strong>Description:</strong> ${details.description || 'N/A'}</p>
            <h4>Groups</h4>
            ${(details.groups && details.groups.length > 0) ? `<ul>${details.groups.map(g => `<li>${g}</li>`).join('')}</ul>` : '<p>No groups assigned.</p>'}

            <div class="details-header"><h4>Parent Rules</h4>${parentExpandBtn}</div>
            ${renderList(details.parents)}

            <div class="details-header"><h4>Child Rules</h4>${childExpandBtn}</div>
            
            ${renderList(details.children)}
        `;
    }
}

class StatsPanel {
    constructor(visualizer) {
        this.visualizer = visualizer;
        this.panel = document.getElementById("statsPanel");
        this.content = document.getElementById("statsContent");
        this.isOpen = false;
        document.getElementById("statsCloseBtn").addEventListener("click", () => this.hide());
    }
    show() {
        this.content.innerHTML = `<h3>Graph Statistics</h3><p><i>Loading...</i></p>`;
        this.panel.classList.add("visible");
        this.isOpen = true;
        fetchJSON('/api/stats').then(stats => this.render(stats)).catch(error => {
            this.content.innerHTML = `<h3>Graph Statistics</h3><p style="color: #ff8a8a;">Could not load statistics.</p>`;
        });
    }
    hide() {
        this.panel.classList.remove("visible");
        this.isOpen = false;
    }
    render(stats) {
        // Helper for rendering standard lists of nodes with counts
        const renderStatsList = (items, title) => {
            if (!items || items.length === 0) return `<h4>${title}</h4><p>No data.</p>`;
            let listHtml = `<h4>${title}</h4><ul>`;
            items.forEach(item => {
                const clickAction = `onclick="window.visualizer.handleSearchById('${item.id}')"`;
                let detail = item.count !== undefined ? `(${item.count})` : '';
                listHtml += `<li class="stats-item" ${clickAction}><strong>${item.id}</strong> ${detail}</li>`;
            });
            listHtml += '</ul>';
            return listHtml;
        };
        
        const renderAllCycles = (stats) => {
            const selfLoops = (stats.self_loops || []).map(loop => [loop.id, loop.id]);
            const multiNodeCycles = stats.cycles || [];
            const allCycles = [...selfLoops, ...multiNodeCycles];
            
            if (allCycles.length === 0) {
                return `<h4>Detected Cycles</h4><p style="color: #8f8;">No cycles detected. The graph is a DAG (Directed Acyclic Graph).</p>`;
            }
            
            let listHtml = `<h4 style="color: #ff8a8a;">Detected Cycles (${allCycles.length} found)</h4>
                        <p style="color: #ff8a8a; font-size: 0.9em;">Warning: Cycles indicate circular dependencies.</p>
                        <div class="cycle-container">`;
            
            allCycles.forEach((cycle, index) => {
                // For display, we want to show the path, e.g., A -> A or A -> B -> A
                // For highlighting, we only need the unique nodes.
                const displayNodes = cycle;
                const uniqueNodes = [...new Set(cycle)];
                const nodeIdsString = uniqueNodes.join(',');
                const isSelfLoop = uniqueNodes.length === 1;
                
                listHtml += `
                <div class="cycle-card">
                    <div class="cycle-header">
                        <span>${isSelfLoop ? 'Self-Loop' : `Cycle #${index + 1 - selfLoops.length}`}</span>
                        <button class="cycle-jump-btn" onclick="window.visualizer.highlightCycle('${nodeIdsString}')">
                            View on Graph
                        </button>
                    </div>
                    <div class="cycle-path">
                        ${displayNodes.map(nodeId => 
                `<div class="cycle-node" onclick="window.visualizer.handleSearchById('${nodeId}')">
                                ${nodeId}
                            </div>`
            ).join('<div class="cycle-arrow">→</div>')}
                    </div>
                </div>
            `;
        });
        
        listHtml += '</div>';
        return listHtml;
    };
    
    this.content.innerHTML = `
        <h3>Graph Statistics</h3>
        ${renderStatsList(stats.top_direct_descendants, "Most Direct Children")}
        ${renderStatsList(stats.top_indirect_descendants, "Most Total Children (Highest Impact)")}
        ${renderStatsList(stats.top_direct_ancestors, "Most Direct Parents")}
        ${renderStatsList(stats.top_indirect_ancestors, "Most Total Parents (Complex Dependencies)")}
        ${renderStatsList(stats.isolated_rules, "Isolated Rules")}
        <hr class="stats-divider">
        ${renderAllCycles(stats)}
    `;
}
}

class HeatmapModal {
    constructor() {
        this.modal = document.getElementById("heatmapModal");
        this.content = document.getElementById("heatmapContent");
        this.isOpen = false;
        this.requestSeq = 0;
        this.currentBlockSize = 100;
        this.currentK = 1;
        this.zoomInitialized = false;
    }
    show() {
        this.modal.classList.add("visible");
        this.isOpen = true;
        this.ensureDOM();
        this.setupZoom();
        this.render(this.currentBlockSize);
    }
    hide() {
        if (this.modal) {
            this.modal.classList.remove("visible");
        }
        this.isOpen = false;
    }
    pickBlockSize(k) {
        if (k >= 8) return 1;
        if (k >= 4) return 10;
        if (k >= 2) return 50;
        if (k >= 1) return 100;
        if (k >= 0.5) return 250;
        return 500;
    }
    pickThresholds(blockSize) {
        switch (blockSize) {
            case 10: return [1, 2, 6, 8];
            case 50: return [1, 10, 30, 40];
            case 100: return [1, 20, 60, 80];
            case 250: return [1, 50, 150, 200];
            case 500: return [1, 100, 300, 400];
            default: return [1];
        }
    }
    ensureDOM() {
        if (document.getElementById("heatmapContainer")) return;
        const container = document.createElement("div");
        container.id = "heatmapContainer";
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg" );
        svg.id = "heatmapSvg";
        svg.innerHTML = '<g id="heatmapViewport"></g>';
        const loader = document.createElement("div");
        loader.id = "heatmapLoader";
        loader.className = "loader-overlay";
        loader.innerHTML = '<div class="spinner"></div>';
        const textOverlay = document.createElement("div");
        textOverlay.id = "heatmapOverlay";
        container.append(svg, loader, textOverlay);
        this.content.appendChild(container);
    }
    setupZoom() {
        if (this.zoomInitialized) return;
        const svg = d3.select("#heatmapSvg");
        const viewport = d3.select("#heatmapViewport");
        const zoom = d3.zoom().scaleExtent([0.1, 10]).on("zoom", (event) => {
            this.currentK = event.transform.k;
            viewport.attr("transform", event.transform.toString());
            const newBlockSize = this.pickBlockSize(this.currentK);
            if (newBlockSize !== this.currentBlockSize) {
                this.render(newBlockSize);
            }
        });
        svg.call(zoom);
        this.zoomInitialized = true;
    }
    render(blockSize) {
        const container = document.getElementById("heatmapContainer");
        const svg = d3.select("#heatmapSvg");
        const viewport = d3.select("#heatmapViewport");
        if (!container) return;
        const w = container.clientWidth || 800;
        const h = container.clientHeight || 600;
        svg.attr("width", w).attr("height", h);
        const seq = ++this.requestSeq;
        this.showLoader();
        fetchJSON(`/api/heatmap?block_size=${blockSize}`).then(data => {
            if (seq !== this.requestSeq) return;
            const blocks = data.blocks || [];
            const cellSize = 12;
            const cols = Math.max(1, Math.floor(w / cellSize));
            const thresholds = this.pickThresholds(blockSize);
            const range = ["#444444", "#8B0000", "#B22222", "#FF4500", "#FF0000"].slice(0, thresholds.length + 1);
            const scale = d3.scaleThreshold().domain(thresholds).range(range);
            const colorFn = blockSize === 1 ? d => (d.count > 0 ? "#FF0000" : "#444444") : d => scale(d.count || 0);
            const temp = viewport.append("g").attr("class", "temp-heatmap");
            temp.selectAll("rect").data(blocks, d => d.id).enter().append("rect").attr("width", cellSize - 2).attr("height", cellSize - 2).attr("x", (d, i) => (i % cols) * cellSize).attr("y", (d, i) => Math.floor(i / cols) * cellSize).attr("fill", d => colorFn(d)).append("title").text(d => blockSize === 1 ? `Rule ID: ${d.id}\n${d.count > 0 ? "Used" : "Unused"}` : `Rule Range: ${d.id}\nUsed IDs: ${d.count || 0}`);
            viewport.selectAll("g.heatmap").remove();
            temp.attr("class", "heatmap");
            this.hideLoader();
            this.currentBlockSize = blockSize;
            const overlay = document.getElementById("heatmapOverlay");
            if (overlay) {
                overlay.innerHTML = `Each block represents ${this.currentBlockSize} rules. <strong>(Press Esc to close)</strong>`;
            }
        }).catch(err => {
            if (seq !== this.requestSeq) return;
            console.error("Heatmap fetch error:", err);
            this.hideLoader();
        });
    }
    showLoader() {
        const el = document.getElementById("heatmapLoader");
        if (el) el.style.display = "flex";
    }
    hideLoader() {
        const el = document.getElementById("heatmapLoader");
        if (el) el.style.display = "none";
    }
}

// =================================================================================
// 3. MAIN CONTROLLER CLASS (GraphVisualizer)
// =================================================================================

class GraphVisualizer {
    constructor(canvasSelector) {
        this.nodes = [];
        this.links = [];
        this.nodeMap = new Map();
        this.highlightedNodeId = null;
        this.highlightedCycleIds = new Set(); 
        this.displayedRuleIDs = new Set();
        this.simulationPausedByKey = false;
        this.transform = d3.zoomIdentity;
        this.canvas = d3.select(canvasSelector);
        this.context = this.canvas.node().getContext("2d");
        const rect = this.canvas.node().getBoundingClientRect();
        this.width = rect.width;
        this.height = rect.height;
        this.devicePixelRatio = window.devicePixelRatio || 1;
        this.canvas.attr('width', this.width * this.devicePixelRatio).attr('height', this.height * this.devicePixelRatio);
        this.context.scale(this.devicePixelRatio, this.devicePixelRatio);
        this.focusModeEnabled = true;
        this.focusedContextIds = new Set();
        this.notificationManager = new NotificationManager();
        this.detailsPanel = new DetailsPanel(this);
        this.statsPanel = new StatsPanel(this);
        this.heatmapModal = new HeatmapModal();
        
        this.simulation = d3.forceSimulation()
        .force("link", d3.forceLink().id(d => d.id).distance(150))
        .force("charge", d3.forceManyBody()
            .strength(-150)
            .theta(0.9)
            .distanceMax(1000)  // ignore charge beyond this distance
        )
        .force("collision", d3.forceCollide().radius(d => d.__radius + 2))
        .force("center", d3.forceCenter(this.width / 2, this.height / 2));
        let lastRender = 0;
        this.simulation.on("tick", () => {
            const now = performance.now();
            if (now - lastRender > 30) {  // about 33 fps max
                this.render();
                lastRender = now;
            }
        });
        // Slower decay means more time to stabilize before stopping.
        // The default is ~0.0228. We're making it cool down much slower.
        this.simulation.alphaDecay(0.025);
        // Stop the simulation when energy is low, but not practically zero.
        // This prevents excessive "jitter" at the end.
        this.simulation.alphaMin(0.0001);
        this.simulation.velocityDecay(0.6);
        this.zoom = d3.zoom().scaleExtent([0.02, 5]).on("zoom", e => { this.transform = e.transform; this.render(); });
        this.canvas.call(this.zoom);
        
        this.initializeEventListeners();
        this.resetGraph();
    }
    
    render() {
        this.context.save();
        this.context.clearRect(0, 0, this.width * this.devicePixelRatio, this.height * this.devicePixelRatio);
        this.context.translate(this.transform.x, this.transform.y);
        this.context.scale(this.transform.k, this.transform.k);
        this.context.lineWidth = 1.5 / this.transform.k;

        if (this.linkGroups) {
            for (const [color, links] of Object.entries(this.linkGroups)) {
                this.context.beginPath();
                for (let link of links) {
                    this.context.moveTo(link.source.x, link.source.y);
                    this.context.lineTo(link.target.x, link.target.y);
                }
                this.context.strokeStyle = color;
                this.context.stroke();
            }
        }
        if (this.transform.k > 0.6) {
            for (let link of this.links) {
                const edgeColor = STYLES.edges[link.relation_type] || STYLES.edges.unknown;
                this.context.fillStyle = edgeColor;
                this.drawArrowhead(link.source, link.target);
            }
        }

        const k = this.transform.k;
        const nodeGroups = { default: [], expandable: [], collapsed: [] };

        for (let node of this.nodes) {
            let styleKey = "default";
            let radius = 10;

            if (this.focusModeEnabled && this.focusedContextIds.size > 0) {
                if (this.focusedContextIds.has(node.id)) {
                    styleKey = node.expandable && !node.is_expanded ? "expandable" : "default";
                } else {
                    styleKey = "collapsed";
                    radius = 5;
                }
            } else {
                styleKey = node.expandable && !node.is_expanded ? "expandable" : "default";
            }

            node.__drawStyle = styleKey;
            node.__radius = radius;
            nodeGroups[styleKey].push(node);
        }

        for (const [styleKey, nodes] of Object.entries(nodeGroups)) {
            if (nodes.length === 0) continue;
            this.context.beginPath();
            for (let node of nodes) {
                this.context.moveTo(node.x + node.__radius, node.y);
                this.context.arc(node.x, node.y, node.__radius, 0, 2 * Math.PI);
            }
            this.context.fillStyle = STYLES.nodes[styleKey];
            this.context.fill();
        }

        if (this.highlightedNodeId) {
            const node = this.nodeMap.get(this.highlightedNodeId);
            if (node) {
                this.context.beginPath();
                this.context.arc(node.x, node.y, node.__radius || 10, 0, 2 * Math.PI);
                this.context.strokeStyle = STYLES.nodes.highlight;
                this.context.lineWidth = 3 / this.transform.k;
                this.context.stroke();
            }
        }

        if (k >= 0.4) {
            for (let node of this.nodes) {
                if (
                    !this.focusModeEnabled ||
                    this.focusedContextIds.size === 0 ||
                    this.focusedContextIds.has(node.id)
                ) {
                    this.context.fillStyle = STYLES.nodes.text;
                    this.context.font = `${(k >= 1.0 ? 12 / k : 10)}px sans-serif`;
                    this.context.fillText(node.id, node.x + 15, node.y + 4);
                }
            }
        }

        this.context.restore();
        this.buildLegend();
        this.drawCounter();
    }
    
    updateGraph(newNodesData, newLinksData, onUpdateComplete = null) {
        const newIds = new Set((newNodesData || []).map(n => n.id));
        (newNodesData || []).forEach(newNode => {
            if (!this.nodeMap.has(newNode.id)) {
                this.nodeMap.set(newNode.id, newNode);
                this.displayedRuleIDs.add(newNode.id);
            } else {
                Object.assign(this.nodeMap.get(newNode.id), newNode);
            }
        });
        this.nodes = Array.from(this.nodeMap.values());
        const linkSet = new Set(this.links.map(l => `${l.source.id}-${l.target.id}`));
        if (!this.linkGroups) this.linkGroups = {};
        (newLinksData || []).forEach(newLink => {
            const linkId = `${newLink.source}-${newLink.target}`;
            if (!linkSet.has(linkId) && this.nodeMap.has(newLink.source) && this.nodeMap.has(newLink.target)) {
                const linkObj = { 
                    ...newLink, 
                    source: this.nodeMap.get(newLink.source), 
                    target: this.nodeMap.get(newLink.target) 
                };
                this.links.push(linkObj);
                linkSet.add(linkId);

                // Group link by color for batched rendering
                const color = STYLES.edges[newLink.relation_type] || STYLES.edges.unknown;
                if (!this.linkGroups[color]) this.linkGroups[color] = [];
                this.linkGroups[color].push(linkObj);
            }
        });
        if (newIds.size > 0) {
            this.linkUpExistingNodes();
        }
        this.nodes.forEach(node => {
            const childrenIds = node.children_ids || [];
            node.expandable = childrenIds.length > 0 && !childrenIds.every(childId => this.displayedRuleIDs.has(childId));
            node.is_expanded = childrenIds.length === 0 || !node.expandable;
        });
        if (onUpdateComplete) {
            this.simulation.on("tick.callback", () => {
                onUpdateComplete();
                this.simulation.on("tick.callback", null);
            });
        }
        this.simulation.nodes(this.nodes);
        this.simulation.force("link").links(this.links);
        this.simulation.alpha(1).restart();
    }

    linkUpExistingNodes() {
        fetchJSON('/api/edges', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: Array.from(this.displayedRuleIDs) }),
        }).then(data => {
            if (data.edges && data.edges.length > 0) {
                this.updateGraph([], data.edges);
            }
        });
    }
    
    expandNode(nodeId) {
        fetchJSON(`/api/nodes?id=${nodeId}&neighbors=children&displayed=${this.getDisplayedIds()}`).then(data => {
            this.updateGraph(data.nodes, data.edges);
            const parentNode = this.nodeMap.get(nodeId);
            if (parentNode) {
                this.detailsPanel.show(parentNode);
                if (this.highlightedNodeId === nodeId && this.focusModeEnabled) {
                    this.updateFocusContext(nodeId);  // refresh focus after expansion
                    this.render();
                }
            }
        });
    }
    
    expandAllParents(nodeId, parentIdsString) {
        const parentIds = parentIdsString.split(',').filter(id => !this.displayedRuleIDs.has(id));
        if (parentIds.length === 0) {
            this.notificationManager.show("All parent nodes are already displayed.");
            return;
        }
        fetchJSON(`/api/nodes?ids=${parentIds.join(',')}&displayed=${this.getDisplayedIds()}`).then(data => {
            this.updateGraph(data.nodes, data.edges);
            const parentNode = this.nodeMap.get(nodeId);
            if (parentNode) {
                this.detailsPanel.show(parentNode);
                if (this.highlightedNodeId === nodeId && this.focusModeEnabled) {
                    this.updateFocusContext(nodeId);  // refresh focus after expansion
                    this.render();
                }
            }
        });
    }
    
    drawArrowhead(source, target) {
        const headLength = 6, nodeRadius = 10;
        const angle = Math.atan2(target.y - source.y, target.x - source.x);
        const tipX = target.x - nodeRadius * Math.cos(angle);
        const tipY = target.y - nodeRadius * Math.sin(angle);
        this.context.beginPath();
        this.context.moveTo(tipX, tipY);
        this.context.lineTo(tipX - headLength * Math.cos(angle - Math.PI / 6), tipY - headLength * Math.sin(angle - Math.PI / 6));
        this.context.lineTo(tipX - headLength * Math.cos(angle + Math.PI / 6), tipY - headLength * Math.sin(angle + Math.PI / 6));
        this.context.closePath();
        this.context.fill();
    }
    
    buildLegend() {
        const nodeLegendData = [{ label: "Expandable Node", color: STYLES.nodes.expandable }, { label: "Default Node", color: STYLES.nodes.default }];
        const edgeLegendData = [{ label: "if_sid", color: STYLES.edges.if_sid }, { label: "if_matched_sid", color: STYLES.edges.if_matched_sid }, { label: "if_group", color: STYLES.edges.if_group }, { label: "if_matched_group", color: STYLES.edges.if_matched_group }, { label: "No parent", color: STYLES.edges.no_parent }, { label: "Unknown", color: STYLES.edges.unknown }];
        let legendY = 30;
        this.context.font = "14px sans-serif";
        this.context.fillStyle = STYLES.legend.text;
        nodeLegendData.forEach(item => {
            this.context.beginPath();
            this.context.arc(20, legendY, 8, 0, 2 * Math.PI);
            this.context.fillStyle = item.color;
            this.context.fill();
            this.context.fillStyle = STYLES.legend.text;
            this.context.fillText(item.label, 35, legendY + 5);
            legendY += 25;
        });
        legendY += 20;
        edgeLegendData.forEach(item => {
            this.context.beginPath();
            this.context.moveTo(10, legendY);
            this.context.lineTo(40, legendY);
            this.context.strokeStyle = item.color;
            this.context.lineWidth = 4;
            this.context.stroke();
            this.context.fillText(item.label, 55, legendY + 5);
            legendY += 25;
        });
    }
    
    drawCounter() {
        const counterText = `Nodes: ${this.nodes.length} | Edges: ${this.links.length}`;
        this.context.font = "14px sans-serif";
        this.context.fillStyle = STYLES.legend.text;
        this.context.textAlign = "left";
        this.context.fillText(counterText, 20, this.height - 20);
    }
    
    findNodeAt(x, y) {
        const [ix, iy] = this.transform.invert([x, y]);
        const radiusSq = 100 / (this.transform.k * this.transform.k);

        for (let i = this.nodes.length - 1; i >= 0; i--) {
            const node = this.nodes[i];
            const dx = ix - node.x;
            const dy = iy - node.y;

            if (dx * dx + dy * dy < radiusSq) {
                // Skip collapsed nodes
                if (this.focusedContextIds.size > 0 && !this.focusedContextIds.has(node.id)) {
                    continue;
                }
                return node;
            }
        }
        return null;
    }
    
    handleSearch() {
        const searchInput = document.getElementById("searchBox").value.trim();
        if (!searchInput) return;
        this.clearHighlight();
        if (this.nodeMap.has(searchInput)) {
            this.highlightAndCenterNode(searchInput);
        } else {
            fetchJSON(`/api/nodes?mode=search&id=${searchInput}&displayed=${this.getDisplayedIds()}`).then(data => {
                this.updateGraph(data.nodes, data.edges, () => this.highlightAndCenterNode(searchInput));
            });
        }
    }
    
    handleSearchById(ruleId) {
        if (this.statsPanel.isOpen) this.statsPanel.hide();
        document.getElementById("searchBox").value = ruleId;
        this.handleSearch();
    }
    
    highlightAndCenterNode(nodeId) {
        const node = this.nodeMap.get(nodeId);
        if (!node) return;
        this.highlightedNodeId = nodeId;
        this.detailsPanel.show(node);
        this.updateFocusContext(nodeId);
        this.render();
        if (node.x !== undefined && node.y !== undefined) {
            node.fx = node.x;
            node.fy = node.y;
            const newTransform = d3.zoomIdentity.translate(this.width / 2, this.height / 2).scale(Math.max(this.transform.k, 1.2)).translate(-node.x, -node.y);
            this.canvas.transition().duration(750).call(this.zoom.transform, newTransform);
        }
    }

    updateFocusContext(nodeId) {
        const node = this.nodeMap.get(nodeId);
        if (!node) {
            this.focusedContextIds.clear();
            return;
        }

        const neighbors = new Set([nodeId]);

        // Children in graph
        for (let childId of (node.children_ids || [])) {
            if (this.displayedRuleIDs.has(childId)) {
                neighbors.add(childId);
            }
        }

        // Parents in graph
        for (let link of this.links) {
            if (link.target.id === nodeId) {
                neighbors.add(link.source.id);
            }
        }

        this.focusedContextIds = neighbors;
    }

    
    clearHighlight() {
        if (this.highlightedNodeId && this.nodeMap.has(this.highlightedNodeId)) {
            const node = this.nodeMap.get(this.highlightedNodeId);
            node.fx = null;
            node.fy = null;
        }
        this.highlightedNodeId = null;
        this.highlightedCycleIds.clear();
        this.focusedContextIds.clear(); 
        this.detailsPanel.hide();
        this.render();
    }
    
    resetGraph() {
        this.nodes = [];
        this.links = [];
        this.nodeMap.clear();
        this.displayedRuleIDs.clear();
        this.linkGroups = {};
        this.context.save();
        this.context.clearRect(
            0,
            0,
            this.width * this.devicePixelRatio,
            this.height * this.devicePixelRatio
        );
        this.context.restore();

        fetchJSON("/api/nodes?mode=root").then(data => {
            this.updateGraph(data.nodes, data.edges);
            this.canvas
                .transition()
                .duration(750)
                .call(this.zoom.transform, d3.zoomIdentity);
        });
    }

    getDisplayedIds() {
        return Array.from(this.displayedRuleIDs).join(",");
    }
    
    highlightCycle(nodeIdsString) {
        const nodeIds = nodeIdsString.split(',');
        if (!nodeIds.length) return;
        
        this.clearHighlight(); // Clear previous state
        
        this.highlightedCycleIds = new Set(nodeIds);
        
        // Re-render to show the highlights
        this.render();
        
        // Center the view on the first node of the cycle
        const firstNode = this.nodeMap.get(nodeIds[0]);
        if (firstNode && firstNode.x !== undefined) {
            const newTransform = d3.zoomIdentity
            .translate(this.width / 2, this.height / 2)
            .scale(Math.max(this.transform.k, 1.0)) // Zoom to at least 1.0
            .translate(-firstNode.x, -firstNode.y);
            this.canvas.transition().duration(750).call(this.zoom.transform, newTransform);
        }
        
        this.statsPanel.hide(); // Hide panel to see the graph
    }
    
    
    initializeEventListeners() {
        document.getElementById("resetZoom").addEventListener("click", () => this.handleSearchById('0'));
        document.getElementById("resetGraph").addEventListener("click", () => this.resetGraph());
        document.getElementById("searchBtn").addEventListener("click", () => this.handleSearch());
        document.getElementById("searchBox").addEventListener("keyup", e => { if (e.key === "Enter") this.handleSearch(); });
        document.getElementById("showStatsBtn").addEventListener("click", () => this.statsPanel.show());
        document.getElementById("showHeatmapBtn").addEventListener("click", () => this.heatmapModal.show());
        document.addEventListener("keydown", e => {
            if (e.key === "Escape") {
                if (this.heatmapModal.isOpen) this.heatmapModal.hide();
                else if (this.highlightedNodeId) this.clearHighlight();
                else if (this.statsPanel.isOpen) this.statsPanel.hide();
            } else if (e.key === " " && document.activeElement.tagName !== 'INPUT') {
                e.preventDefault();
                this.simulationPausedByKey = !this.simulationPausedByKey;
                if (this.simulationPausedByKey) {
                    this.simulation.stop();
                    this.notificationManager.show("Simulation paused");
                } else {
                    this.simulation.alpha(0.3).restart();
                    this.notificationManager.show("Simulation resumed");
                }
            }
        });
        document.getElementById("toggleFocusBtn")
            .addEventListener("click", () => {
                this.focusModeEnabled = !this.focusModeEnabled;
                const btn = document.getElementById("toggleFocusBtn");
                btn.textContent = this.focusModeEnabled ? "Toggle focus off" : "Toggle focus on";

                if (!this.focusModeEnabled) {
                    // Disable focus mode immediately
                    this.focusedContextIds.clear();
                    this.render();
                } else if (this.highlightedNodeId) {
                    // Reapply focus if a node is currently highlighted
                    this.updateFocusContext(this.highlightedNodeId);
                    this.render();
                }
            });
        this.canvas.on("click", e => { 
            const node = this.findNodeAt(e.offsetX, e.offsetY); 
            if (node) {
                this.highlightAndCenterNode(node.id); 
            } else if (this.highlightedNodeId || this.highlightedCycleIds.size > 0) {
                this.clearHighlight();
            }
        });
        this.canvas.on("contextmenu", e => {
            e.preventDefault();
            e.stopPropagation();
        });
        this.canvas.call(d3.drag().container(this.canvas.node()).subject(e => this.findNodeAt(e.x, e.y)).on("start", e => { if (!e.active) this.simulation.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; }).on("drag", e => { e.subject.fx = e.x; e.subject.fy = e.y; }).on("end", e => { if (!e.active) this.simulation.alphaTarget(0); if (!this.simulationPausedByKey) { e.subject.fx = null; e.subject.fy = null; } }));
    }
}

// =================================================================================
// 4. GLOBAL HELPER & INITIALIZATION
// =================================================================================

async function fetchJSON(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const message = errorData.error || `Error: ${response.status} ${response.statusText}`;
            if (window.visualizer) window.visualizer.notificationManager.show(message);
            throw new Error(message);
        }
        return await response.json();
    } catch (error) {
        // Only show generic message for true network errors (e.g., server down, DNS fail)
        if (window.visualizer && error instanceof TypeError) {
            window.visualizer.notificationManager.show("Server not reachable. Please check connection.");
        }
        throw error;
    }
}

window.visualizer = new GraphVisualizer('canvas');
