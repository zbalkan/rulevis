'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync('src/internal/static/graph.js', 'utf8')
    .replace(/window\.visualizer = new GraphVisualizer\('canvas'\);\s*$/,
        'globalThis.GraphVisualizer = GraphVisualizer; globalThis.DetailsPanel = DetailsPanel;');

function load(extra = {}) {
    const sandbox = { window: {}, URLSearchParams, ...extra };
    vm.runInNewContext(source, sandbox);
    return sandbox;
}

test('correlation warning starts collapsed and omits duplicated group disclaimer', () => {
    const sandbox = load();
    const state = {
        visualizer: { displayedRuleIDs: new Set() },
        content: { innerHTML: '' },
    };
    sandbox.DetailsPanel.prototype.render.call(state, {
        id: '1234', level: '6', description: 'test', groups: ['example'],
        parents: [{ id: '99', load_order_candidate: false }],
        children: [],
        correlation_warnings: [{
            code: 'GROUP_LOAD_ORDER', message: 'Delayed dependency',
        }],
    });
    const html = state.content.innerHTML;
    assert.match(html, /<details class="correlation-warnings"/);
    assert.match(html, /<summary>Potential correlation gaps/);
    assert.match(html, /GROUP_LOAD_ORDER/);
    assert.doesNotMatch(html, /<details class="correlation-warnings"[^>]*\bopen\b/);
    assert.doesNotMatch(html, /Group, level and temporal-source eligibility/);
});

test('resize updates backing resolution, simulation center and redraws once', () => {
    const d3 = { zoomIdentity: {
        translate(x, y) { this.x = x; this.y = y; return this; },
        scale(k) { this.k = k; return this; },
    } };
    const { GraphVisualizer } = load({ d3, window: { devicePixelRatio: 2 } });
    const attrs = {};
    const calls = [];
    const center = {
        x(value) { calls.push(['x', value]); return this; },
        y(value) { calls.push(['y', value]); return this; },
    };
    const state = {
        canvas: {
            node() { return { getBoundingClientRect() { return { width: 640, height: 480 }; } }; },
            attr(key, value) { attrs[key] = value; return this; },
            call() { calls.push('zoom'); return this; },
        },
        width: 800, height: 600, devicePixelRatio: 1,
        context: { setTransform(...values) { calls.push(['transform', ...values]); } },
        simulation: { force(name) { assert.equal(name, 'center'); return center; } },
        zoom: { transform() {} },
        transform: { x: 0, y: 0, k: 1 },
        render() { calls.push('render'); },
    };
    GraphVisualizer.prototype.resizeCanvas.call(state);
    assert.equal(attrs.width, 1280);
    assert.equal(attrs.height, 960);
    assert.equal(state.width, 640);
    assert.equal(state.height, 480);
    assert.deepEqual(calls.filter(c => Array.isArray(c) && c[0] === 'transform'),
        [['transform', 2, 0, 0, 2, 0, 0]]);
    assert.ok(calls.some(c => Array.isArray(c) && c[0] === 'x' && c[1] === 320));
    assert.ok(calls.some(c => Array.isArray(c) && c[0] === 'y' && c[1] === 240));
    assert.equal(calls.filter(c => c === 'render').length, 1);
    GraphVisualizer.prototype.resizeCanvas.call(state);
    assert.equal(calls.filter(c => c === 'render').length, 1);
});

test('resize notifications are debounced until layout settles', () => {
    const callbacks = [];
    const scheduled = new Map();
    let nextId = 0;
    const window = { addEventListener(name, callback) {
        assert.equal(name, 'resize');
        callbacks.push(callback);
    } };
    class FakeResizeObserver {
        constructor(callback) { this.callback = callback; callbacks.push(callback); }
        observe(container) { assert.ok(container); }
    }
    const { GraphVisualizer } = load({
        window, ResizeObserver: FakeResizeObserver,
        setTimeout(callback) { const id = ++nextId; scheduled.set(id, callback); return id; },
        clearTimeout(id) { scheduled.delete(id); },
    });
    let resized = 0;
    const state = {
        canvas: { node() { return { parentElement: {} }; } },
        resizeCanvas() { ++resized; },
    };
    GraphVisualizer.prototype.initializeResizeHandling.call(state);
    assert.equal(callbacks.length, 2);
    callbacks[0]();
    callbacks[1]();
    callbacks[0]();
    assert.equal(scheduled.size, 1);
    assert.equal(resized, 0);
    [...scheduled.values()][0]();
    assert.equal(resized, 1);
});

test('cycle navigation loads missing members before highlighting and fitting all nodes', async () => {
    const requested = [];
    const zooms = [];
    const d3 = { zoomIdentity: {
        translate() { return this; },
        scale() { return this; },
    } };
    const fetch = async url => {
        requested.push(url);
        return {
            ok: true,
            json: async () => ({ nodes: [{ id: '2', x: 200, y: 300 }], edges: [] }),
        };
    };
    const { GraphVisualizer } = load({ fetch, d3 });
    const nodes = new Map([['1', { id: '1', x: 100, y: 100 }]]);
    const state = {
        cycleRequestId: 0,
        nodeMap: nodes,
        highlightedCycleIds: new Set(),
        focusedContextIds: new Set(),
        width: 800, height: 600,
        getDisplayedIds() { return '1'; },
        updateGraph(added) { for (const node of added) nodes.set(node.id, node); },
        clearHighlight() { ++this.cycleRequestId; this.highlightedCycleIds.clear(); },
        statsPanel: { hide() { requested.push('hide'); } },
        canvas: {
            transition() { return this; },
            duration() { return this; },
            call() { zooms.push(true); return this; },
        },
        zoom: { transform() {} },
        render() { requested.push('render'); },
    };
    await GraphVisualizer.prototype.highlightCycle.call(state, '1,2,1');
    assert.ok(requested[0].startsWith('/api/nodes?'));
    assert.equal(new URL('http://localhost' + requested[0]).searchParams.get('ids'), '2');
    assert.deepEqual([...state.highlightedCycleIds], ['1', '2']);
    assert.deepEqual([...state.focusedContextIds], ['1', '2']);
    assert.equal(zooms.length, 1);
    assert.ok(requested.includes('hide'));
});
