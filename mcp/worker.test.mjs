import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import worker, { KeyStore } from './worker.mjs';

function fixture() {
  const entries = new Map();
  const storage = {
    get: async (key) => structuredClone(entries.get(key)),
    put: async (key, value) => entries.set(key, structuredClone(value)),
    list: async ({ prefix }) => new Map([...entries].filter(([key]) => key.startsWith(prefix))),
    transaction: async (run) => run(storage),
  };
  const env = { ADMIN_TOKEN: 'a'.repeat(64), KEY_ENCRYPTION_SECRET: 'b'.repeat(64) };
  const store = new KeyStore({ storage }, env);
  env.KEYS = { idFromName: (name) => name, get: () => ({
    fetch: (url, options) => store.fetch(new Request(url, options)),
  }) };
  const send = (path, { method = 'GET', token, body, headers = {} } = {}) => worker.fetch(
    new Request('https://worker.example' + path, { method, headers: {
      'Content-Type': 'application/json', ...headers,
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
    }, body: body === undefined ? undefined : JSON.stringify(body) }), env);
  const create = () => send('/admin/keys', {
    method: 'POST', token: env.ADMIN_TOKEN, body: { label: '분석팀' },
  });
  const mcp = (token, method, params, headers) => send('/mcp', {
    method: 'POST', token, headers, body: { jsonrpc: '2.0', id: 1, method, params },
  });
  return { entries, env, send, create, mcp };
}

test('administrator can issue, reveal and revoke a key without storing plaintext', async () => {
  const { entries, env, send, create, mcp } = fixture();
  assert.equal((await send('/admin/keys')).status, 401);
  assert.equal((await mcp(env.ADMIN_TOKEN, 'tools/list')).status, 401);
  const response = await create();
  assert.equal(response.status, 201);
  const { key, id } = await response.json();
  assert.match(key, /^si_[a-f0-9]{24}\.[a-f0-9]{64}$/);
  assert.ok(entries.get('key:' + id).ciphertext instanceof ArrayBuffer);
  assert.equal(JSON.stringify([...entries.values()]).includes(key), false);
  assert.equal((await send('/admin/keys', { token: key })).status, 401);
  const list = await (await send('/admin/keys', { token: env.ADMIN_TOKEN })).json();
  assert.equal(list.keys[0].label, '분석팀');
  assert.equal(Object.hasOwn(list.keys[0], 'key'), false);
  const revoke = () => send('/admin/keys/' + id, { method: 'DELETE', token: env.ADMIN_TOKEN });
  const reveal = () => send('/admin/keys/' + id + '/reveal', { method: 'POST', token: env.ADMIN_TOKEN });
  const shown = await reveal();
  assert.equal(shown.headers.get('Cache-Control'), 'no-store');
  assert.equal((await shown.json()).key, key);
  assert.equal((await mcp(key, 'tools/list')).status, 200);
  assert.equal((await revoke()).status, 200);
  assert.equal((await revoke()).status, 200);
  assert.equal(entries.get('key:' + id).ciphertext, undefined);
  assert.equal((await mcp(key, 'tools/list')).status, 401);
  assert.equal((await reveal()).status, 404);
});

test('MCP transport and six public data tools', async (t) => {
  const { send, create, mcp } = fixture();
  const { key } = await (await create()).json();
  const id = 'CVE-2026-1111';
  const archived = 'CVE-2026-2222';
  const snapshot = {
    updatedAt: '2026-11-26T05:00:00Z', collection: { state: 'degraded' },
    cves: [
      { id, title: 'Example', epss: { score: 0.03 }, cvss: 6 },
      { id: 'CVE-2026-3333', epss: { score: 0.5 }, cvss: 9, kev: true },
    ],
    news: [{ title: 'Test advisory', feed: 'KISA 보호나라 · 보안공지', cves: [id] }],
    history: [{ id, type: 'kev' }],
  };
  t.mock.method(globalThis, 'fetch', async (address) => {
    assert.equal(address.origin, 'https://yongseok-mun.github.io');
    if (address.pathname.endsWith('/data.json')) return Response.json(snapshot);
    if (address.pathname.endsWith('/cve-archive.json')) {
      return Response.json({ [archived]: { id: archived, title: 'Archived' } });
    }
    assert.ok(address.pathname.endsWith('/debian-packages.json'));
    return Response.json({ [id]: { example: { bookworm: { status: 'resolved' } } } });
  });
  const initialized = await (await mcp(key, 'initialize', { protocolVersion: '2025-11-25' })).json();
  assert.equal(initialized.result.protocolVersion, '2025-11-25');
  assert.equal((await mcp(key, 'ping', undefined, { 'MCP-Protocol-Version': 'invalid' })).status, 400);
  assert.equal((await send('/mcp', { token: key })).status, 405);
  assert.equal((await mcp(key, 'ping', undefined, { Origin: 'https://other.example' })).status, 403);
  assert.equal((await send('/mcp', { token: key, method: 'POST',
    body: { jsonrpc: '2.0', method: 'notifications/initialized' } })).status, 202);
  const list = await (await mcp(key, 'tools/list')).json();
  assert.equal(list.result.tools.length, 6);
  const call = async (name, args) => (await (await mcp(key, 'tools/call', { name, arguments: args })).json()).result.structuredContent;
  assert.equal((await call('get_snapshot_status')).collectionState, 'degraded');
  assert.equal((await call('list_cves', { view: 'epss' })).items[0].epss.score, 0.5);
  assert.equal((await call('list_cves', { scope: 'archive' })).items[0].id, archived);
  assert.equal((await call('get_cve', { id })).history[0].type, 'kev');
  assert.equal((await call('get_cve', { id: archived })).scope, 'archive');
  assert.equal((await call('list_news', { category: 'kisa', query: id })).total, 1);
  assert.equal((await call('list_changes', { type: 'kev' })).total, 1);
  assert.equal((await call('get_debian_packages', { id })).packages.example.bookworm.status, 'resolved');
  const invalid = await (await mcp(key, 'tools/call', { name: 'list_cves', arguments: { limit: 999 } })).json();
  assert.equal(invalid.error.code, -32602);
  const page = await send('/admin');
  const html = await page.text();
  assert.match(html, /MCP 키 관리/);
  assert.match(page.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
  assert.equal(html.includes(key), false);
  const script = /<script[^>]*>([\s\S]*?)<\/script>/.exec(html)[1];
  assert.doesNotThrow(() => new Function(script));
});

test('repository retains a separate Worker configuration', async () => {
  const config = await readFile(new URL('./wrangler.toml', import.meta.url), 'utf8');
  assert.match(config, /new_sqlite_classes = \["KeyStore"\]/);
  assert.doesNotMatch(config, /ADMIN_TOKEN|KEY_ENCRYPTION_SECRET/);
});
