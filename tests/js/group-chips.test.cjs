'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync('src/internal/static/graph.js', 'utf8')
    .replace("window.visualizer = new GraphVisualizer('canvas');",
        'globalThis.renderGroupChipsForTest = renderGroupChips;');
const sandbox = { window: {} };
vm.runInNewContext(source, sandbox);
const render = sandbox.renderGroupChipsForTest;

test('zero to three groups show without expansion control', () => {
    assert.match(render([]), /No groups assigned/);
    for (let count = 1; count <= 3; count++) {
        const groups = Array.from({ length: count }, (_, i) => `group-${i}`);
        const html = render(groups);
        assert.equal((html.match(/class="rule-group-chip"/g) || []).length, count);
        assert.doesNotMatch(html, /<details/);
    }
});

test('four or more groups start collapsed with a native keyboard-accessible control', () => {
    for (const count of [4, 7, 100]) {
        const groups = Array.from({ length: count }, (_, i) => `group-${i}`);
        const html = render(groups);
        assert.match(html, /<details class="rule-group-overflow">/);
        assert.match(html, new RegExp(`\\+${count - 3} more`));
        assert.match(html, /Show less/);
        assert.match(html, /<summary>/);
        assert.doesNotMatch(html, /aria-label=/);
        // Native summary exposes its own current text and open/closed state.
        // The visible labels are switched by CSS according to details[open].
        assert.equal((html.match(/class="rule-group-chip"/g) || []).length, count);
        assert.equal(html.indexOf('group-0') < html.indexOf('group-3'), true);
    }
});

test('all group values remain escaped, in order, and unmodified', () => {
    const groups = ['<admin>', 'auth&login', 'a"b', "o'hare"];
    const html = render(groups);
    assert.deepEqual(groups, ['<admin>', 'auth&login', 'a"b', "o'hare"]);
    assert.match(html, /&lt;admin&gt;/);
    assert.match(html, /auth&amp;login/);
    assert.match(html, /a&amp;quot;b|a&quot;b/);
    assert.match(html, /o&#039;hare/);
    assert.doesNotMatch(html, /<admin>/);
});

test('both metadata surfaces use the same group rendering helper', () => {
    assert.ok(source.includes('<h4>Groups</h4>'));
    assert.ok(source.includes('${renderGroupChips(details.groups)}'));
    assert.ok(source.includes('<div>${renderGroupChips(details.groups)}</div>'));
});
