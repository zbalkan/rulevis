'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync('src/internal/static/graph.js', 'utf8')
    .replace(
        /window\.visualizer = new GraphVisualizer\('canvas'\);\s*$/,
        '',
    );

test('graph helpers load without a document in a Node VM', () => {
    assert.doesNotThrow(() => vm.runInNewContext(source, { window: {} }));
});

test('closing the notice writes a persistent cookie and removes the banner', () => {
    let click;
    let removed = false;
    const close = {
        addEventListener(name, callback) {
            assert.equal(name, 'click');
            click = callback;
        },
    };
    const banner = { remove() { removed = true; } };
    const document = {
        cookie: '',
        getElementById(id) {
            if (id === 'correlationNoticeClose') return close;
            if (id === 'correlationNotice') return banner;
            return null;
        },
    };
    vm.runInNewContext(source, { window: {}, document });
    assert.equal(typeof click, 'function');
    click();
    assert.match(document.cookie, /^rulevis_correlation_notice_dismissed=1;/);
    assert.match(document.cookie, /Max-Age=31536000/);
    assert.match(document.cookie, /SameSite=Lax/);
    assert.equal(removed, true);
});

test('absent close button does not prevent graph helpers from loading', () => {
    const document = { getElementById() { return null; } };
    assert.doesNotThrow(() => vm.runInNewContext(source, { window: {}, document }));
});
