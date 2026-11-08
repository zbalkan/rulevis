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

test('clicking badge toggles only the overlay', () => {
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
