'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync('src/internal/static/graph.js', 'utf8')
    .replace(
        /window\.visualizer = new GraphVisualizer\('canvas'\);\s*$/,
        'globalThis.GraphVisualizer = GraphVisualizer;',
    );
const sandbox = { window: {} };
vm.runInNewContext(source, sandbox);
const graph = sandbox.GraphVisualizer.prototype;

test('threshold badge is based on if_level, not node level', () => {
    const bounds = graph.thresholdBadgeBounds({
        id: '100030', level: '8', if_level: '5', x: 100, y: 100,
    });
    assert.equal(bounds.label, 'L ≥ 5');
    assert.equal(graph.thresholdBadgeBounds({
        id: '100031', level: '8', x: 100, y: 100,
    }), null);
});

test('badge hit testing and overlay toggling are independent of physics', () => {
    const node = { id: '100030', if_level: '5', x: 100, y: 100 };
    const state = {
        nodes: [node],
        transform: { k: 1, invert: point => point },
        focusModeEnabled: false,
        focusedContextIds: new Set(),
    };
    const b = graph.thresholdBadgeBounds(node);
    state.thresholdBadgeBounds = graph.thresholdBadgeBounds;
    assert.equal(
        graph.findThresholdBadgeAt.call(state, b.x + 3, b.y + 3).id,
        node.id,
    );
    assert.equal(graph.findThresholdBadgeAt.call(state, 0, 0), null);

    let refreshed = 0;
    let rendered = 0;
    state.activeLevelRuleId = null;
    state.levelOverlayRequestId = 0;
    state.levelOverlayEdges = [];
    state.refreshLevelOverlay = () => ++refreshed;
    state.render = () => ++rendered;
    graph.toggleLevelOverlay.call(state, node.id);
    assert.equal(state.activeLevelRuleId, node.id);
    assert.equal(refreshed, 1);
    graph.toggleLevelOverlay.call(state, node.id);
    assert.equal(state.activeLevelRuleId, null);
    assert.equal(state.levelOverlayEdges.length, 0);
    assert.equal(rendered, 1);
});

test('threshold links never become physics links; parallel types survive', () => {
    const nodeA = { id: '100001', children_ids: ['100030'] };
    const nodeB = { id: '100030', if_level: '5', children_ids: [] };
    let physicsLinks = null;
    const simulation = {
        nodes() {},
        force(name) {
            assert.equal(name, 'link');
            return { links(value) { physicsLinks = value; } };
        },
        alpha() { return { restart() {} }; },
    };
    const state = {
        nodeMap: new Map(), displayedRuleIDs: new Set(),
        nodes: [], links: [], linkGroups: {},
        activeLevelRuleId: null,
        simulation, linkUpExistingNodes() {},
    };
    graph.updateGraph.call(state, [nodeA, nodeB], [
        { source: nodeA.id, target: nodeB.id, relation_type: 'if_level' },
        { source: nodeA.id, target: nodeB.id, relation_type: 'if_sid' },
        { source: nodeA.id, target: nodeB.id, relation_type: 'if_group' },
    ]);
    assert.equal(state.links.length, 2);
    assert.equal(physicsLinks.length, 2);
    assert.deepEqual(
        [...state.links.map(link => link.relation_type)].sort(),
        ['if_group', 'if_sid'],
    );
});


test('canvas click on badge opens overlay and empty click clears it', () => {
    const node = { id: '100030', if_level: '5', x: 100, y: 100 };
    const badge = graph.thresholdBadgeBounds(node);
    let redraws = 0;
    let refreshes = 0;
    const state = {
        nodes: [node],
        nodeMap: new Map([[node.id, node]]),
        transform: { k: 1, invert: point => point },
        focusModeEnabled: false,
        focusedContextIds: new Set(),
        highlightedNodeId: null,
        highlightedCycleIds: new Set(),
        activeLevelRuleId: null,
        levelOverlayEdges: [],
        levelOverlayRequestId: 0,
        detailsPanel: { hide() {} },
        thresholdBadgeBounds: graph.thresholdBadgeBounds,
        findThresholdBadgeAt: graph.findThresholdBadgeAt,
        findNodeAt: () => null,
        toggleLevelOverlay: graph.toggleLevelOverlay,
        refreshLevelOverlay: () => { ++refreshes; },
        clearHighlight: graph.clearHighlight,
        render: () => { ++redraws; },
    };
    graph.handleCanvasClick.call(state, {
        offsetX: badge.x + 2, offsetY: badge.y + 2,
    });
    assert.equal(state.activeLevelRuleId, node.id);
    assert.equal(refreshes, 1);

    state.levelOverlayEdges = [{ source: '100001', target: node.id }];
    graph.handleCanvasClick.call(state, { offsetX: 0, offsetY: 0 });
    assert.equal(state.activeLevelRuleId, null);
    assert.equal(state.levelOverlayEdges.length, 0);
    assert.equal(redraws, 1);
});

test('Escape clears an overlay without a highlighted node', () => {
    const state = {
        conditionsModal: { isOpen: false },
        heatmapModal: { isOpen: false },
        statsPanel: { isOpen: false },
        highlightedNodeId: null,
        activeLevelRuleId: '100030',
        levelOverlayEdges: [{}],
        levelOverlayRequestId: 2,
        highlightedCycleIds: new Set(),
        focusedContextIds: new Set(),
        detailsPanel: { hide() {} },
        nodeMap: new Map(),
        render() {},
        clearHighlight: graph.clearHighlight,
    };
    graph.handleEscape.call(state);
    assert.equal(state.activeLevelRuleId, null);
    assert.equal(state.levelOverlayEdges.length, 0);
    assert.equal(state.levelOverlayRequestId, 3);
});


test('selecting another rule clears the selected threshold overlay', () => {
    const old = { id: '100030', if_level: '5', x: 10, y: 10 };
    const next = { id: '100040' };
    let openedDetails = null;
    let redraws = 0;
    const state = {
        nodeMap: new Map([[old.id, old], [next.id, next]]),
        activeLevelRuleId: old.id,
        levelOverlayEdges: [{ source: '100001', target: old.id }],
        levelOverlayRequestId: 7,
        detailsPanel: { show(node) { openedDetails = node.id; } },
        updateFocusContext() {},
        render() { ++redraws; },
    };
    graph.highlightAndCenterNode.call(state, next.id);
    assert.equal(state.activeLevelRuleId, null);
    assert.equal(state.levelOverlayEdges.length, 0);
    assert.equal(state.levelOverlayRequestId, 8);
    assert.equal(openedDetails, next.id);
    assert.equal(redraws, 1);
});

test('selecting the currently annotated rule retains its overlay', () => {
    const node = { id: '100030', if_level: '5' };
    const overlay = [{ source: '100001', target: node.id }];
    const state = {
        nodeMap: new Map([[node.id, node]]),
        activeLevelRuleId: node.id,
        levelOverlayEdges: overlay,
        levelOverlayRequestId: 7,
        detailsPanel: { show() {} },
        updateFocusContext() {},
        render() {},
    };
    graph.highlightAndCenterNode.call(state, node.id);
    assert.equal(state.activeLevelRuleId, node.id);
    assert.equal(state.levelOverlayEdges, overlay);
    assert.equal(state.levelOverlayRequestId, 7);
});


test('zero or shadowed if_level does not produce an active badge', () => {
    const zero = { id: '100001', x: 10, y: 20, if_level: '0' };
    assert.equal(graph.thresholdBadgeBounds(zero), null);
    const shadowed = {
        id: '100002', x: 10, y: 20, if_level: '5',
        selector_precedence: { effective: 'if_sid', shadowed: ['if_level'] },
    };
    assert.equal(graph.thresholdBadgeBounds(shadowed), null);
});

test('details show level-parent counts and shadowed selector notice', () => {
    const state = {
        visualizer: { displayedRuleIDs: new Set() },
        content: { innerHTML: '' },
    };
    const details = {
        id: '100030', description: 'example', level: '8',
        if_level: '5', groups: [], parents: [
            { id: '100020', relation_type: 'if_group', shadowed_by: 'if_level' },
        ], children: [],
        level_parents: { declared: 12, load_order_candidates: 4 },
        selector_precedence: { effective: 'if_level', shadowed: ['if_group'] },
    };
    const detailSandbox = { window: {} };
    vm.runInNewContext(
        source + '\n globalThis.__DetailsPanel = DetailsPanel;',
        detailSandbox,
    );
    const panel = detailSandbox.__DetailsPanel;
    panel.prototype.render.call(state, details);
    assert.match(state.content.innerHTML, /12 declared/);
    assert.match(state.content.innerHTML, /4 load-order candidates/);
    assert.match(state.content.innerHTML, /shadowed by if_level/);
});
