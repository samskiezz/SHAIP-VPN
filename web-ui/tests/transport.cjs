// Exercise the production TypeScript, including API fetch options, without a
// browser or a live account. TypeScript is already a project dependency.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');

function load(file, deps = {}) {
  const js = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../lib', file), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const mod = { exports: {} };
  new Function('exports', 'require', 'module', js)(mod.exports, name => {
    if (!(name in deps)) throw new Error('Unexpected dependency ' + name);
    return deps[name];
  }, mod);
  return mod.exports;
}
const transport = load('transport.ts');
const { apiRequestURL } = transport;

test('browser toggles never establish protection; simulations require explicit preview', () => {
  const { browserProtection } = load('protection.ts');
  for (const preview of [true, false]) {
    for (const requested of [true, false]) {
      for (const nodes of [0, 3]) {
        const state = browserProtection(preview, requested, nodes);
        assert.equal(state.protected, false);
        assert.equal(state.simulatedConnected, preview && requested && nodes > 0);
        assert.equal(state.canSimulate, preview);
        assert.match(state.message, /does not protect|does not route/);
      }
    }
  }
});

test('actual browser page renders an explicit unavailable state', () => {
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const App = load('../pages/app.tsx', {
    react: React,
    'react/jsx-runtime': require('react/jsx-runtime'),
    '@/lib/api': {},
    '@/lib/protection': load('protection.ts'),
  }).default;
  const html = renderToStaticMarkup(React.createElement(App));
  assert.match(html, /VPN protection unavailable in this browser/);
  assert.match(html, /Native VPN required/);
  assert.match(html, /aria-disabled="true"/);
  assert.match(html, /UNVERIFIED/);
  assert.doesNotMatch(html, />SECURED<|>PROTECTED<|>ARMED</);
});

test('remote cleartext and URL credentials are rejected', () => {
  for (const base of ['http://api.example.com', 'http://192.168.1.1', '//api.example.com',
    'https://user:secret@api.example.com', 'https://api.example.com?token=secret', 'https://api.example.com#secret']) {
    assert.throws(() => apiRequestURL(base, '/api/auth/login', 'http://localhost:3000/'));
  }
});
test('HTTPS and same-origin proxy work; HTTP requires both endpoints to be local', () => {
  assert.equal(apiRequestURL('https://api.example.com', '/api/me', 'https://app.example.com/'), 'https://api.example.com/api/me');
  assert.equal(apiRequestURL('', '/api/me', 'https://app.example.com/login'), 'https://app.example.com/api/me');
  assert.equal(apiRequestURL('http://127.0.0.1:8080', '/api/me', 'http://localhost:3000/'), 'http://127.0.0.1:8080/api/me');
  assert.throws(() => apiRequestURL('http://localhost:8080', '/api/me', 'https://app.example.com/'));
  for (const p of ['//evil.example/api/me', '/other', '/api/\\evil', '/api/me#secret']) {
    assert.throws(() => apiRequestURL('https://api.example.com', p));
  }
});
test('credentials are never fetched over remote HTTP and redirects are refused', async () => {
  const oldBase = process.env.NEXT_PUBLIC_API_URL;
  const oldWindow = global.window;
  const oldFetch = global.fetch;
  let calls = 0;
  global.window = { location: { href: 'https://app.example.com/' } };
  global.fetch = async (url, opts) => {
    calls++;
    assert.equal(url, 'https://api.example.com/api/auth/login');
    assert.equal(opts.redirect, 'error');
    assert.equal(opts.referrerPolicy, 'no-referrer');
    assert.equal(opts.cache, 'no-store');
    assert.equal(opts.credentials, 'omit');
    return { status: 200, text: async () => '{"token":"test"}' };
  };
  try {
    process.env.NEXT_PUBLIC_API_URL = 'http://api.example.com';
    const insecure = load('api.ts', { './transport': transport });
    await assert.rejects(insecure.api('/api/auth/login', { method: 'POST', auth: false, body: { password: 'secret' } }), /HTTPS/);
    assert.equal(calls, 0);
    process.env.NEXT_PUBLIC_API_URL = 'https://api.example.com';
    const secure = load('api.ts', { './transport': transport });
    assert.deepEqual(await secure.api('/api/auth/login', { method: 'POST', auth: false, body: { password: 'secret' } }), { token: 'test' });
    assert.equal(calls, 1);
  } finally {
    if (oldBase === undefined) delete process.env.NEXT_PUBLIC_API_URL;
    else process.env.NEXT_PUBLIC_API_URL = oldBase;
    global.window = oldWindow;
    global.fetch = oldFetch;
  }
});
