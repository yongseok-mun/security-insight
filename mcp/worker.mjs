import { bearer, isAdmin, json, KeyStore, randomHex } from './keys.mjs';
import { listTools, resolveTool } from './tools.mjs';
import { adminPage } from './admin.mjs';

export { KeyStore };
const versions = ['2025-11-25', '2025-06-18', '2025-03-26'];
const keyRoutes = /^\/admin\/keys(?:\/[0-9a-f]{24}(?:\/reveal)?)?$/;

async function readJson(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) {
    throw new TypeError('JSON 요청이 필요합니다.');
  }
  const reader = request.body?.getReader();
  if (!reader) throw new TypeError('요청 본문이 비어 있습니다.');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let text = '';
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > 32768) {
      await reader.cancel();
      throw new RangeError('요청 본문이 너무 큽니다.');
    }
    text += decoder.decode(value, { stream: true });
  }
  return JSON.parse(text + decoder.decode());
}

const rpc = (id, result) => json({ jsonrpc: '2.0', id, result });
const failure = (id, code, message, status = 200) =>
  json({ jsonrpc: '2.0', id, error: { code, message } }, status);

async function handleMcp(request) {
  const version = request.headers.get('MCP-Protocol-Version');
  if (version && !versions.includes(version)) return failure(null, -32600, 'Unsupported protocol version', 400);
  let message;
  try {
    message = await readJson(request);
  } catch (error) {
    return failure(null, -32700, 'Invalid JSON request', error instanceof RangeError ? 413 : 400);
  }
  const hasId = message && Object.hasOwn(message, 'id');
  const id = message?.id;
  if (!message || Array.isArray(message) || message.jsonrpc !== '2.0' ||
      typeof message.method !== 'string' ||
      (hasId && typeof id !== 'string' && !Number.isFinite(id))) {
    return failure(null, -32600, 'Invalid Request', 400);
  }
  if (!hasId) return new Response(null, { status: 202 });

  switch (message.method) {
    case 'initialize': {
      const requested = message.params?.protocolVersion;
      if (typeof requested !== 'string') return failure(id, -32602, 'Missing protocolVersion');
      return rpc(id, {
        protocolVersion: versions.includes(requested) ? requested : versions[0],
        capabilities: { tools: {} },
        serverInfo: { name: 'security-insight', version: '1.0.0' },
        instructions: '공개 보안 정보를 조회합니다. updatedAt과 collectionState를 확인하세요.',
      });
    }
    case 'ping':
      return rpc(id, {});
    case 'tools/list':
      return rpc(id, { tools: listTools() });
    case 'tools/call': {
      const args = message.params?.arguments === undefined ? {} : message.params.arguments;
      const handler = resolveTool(message.params?.name, args);
      if (!handler) return failure(id, -32602, 'Unknown tool or invalid arguments');
      try {
        const result = await handler(args);
        const content = [{ type: 'text', text: JSON.stringify(result) }];
        return rpc(id, version === '2025-03-26' ? { content } : { content, structuredContent: result });
      } catch {
        return rpc(id, { isError: true, content: [{ type: 'text',
          text: '게시 데이터를 가져오지 못했습니다. 잠시 후 다시 시도하세요.' }] });
      }
    }
    default:
      return failure(id, -32601, 'Method not found');
  }
}

async function handle(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return json({ error: '허용되지 않은 Origin입니다.' }, 403);

  if (url.pathname === '/admin' && request.method === 'GET') {
    const nonce = randomHex(18);
    return new Response(adminPage(nonce), { headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce +
        "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    } });
  }

  if (keyRoutes.test(url.pathname)) {
    if (!await isAdmin(request, env)) return json({ error: '관리자 인증이 필요합니다.' }, 401);
    let body;
    if (url.pathname === '/admin/keys' && request.method === 'POST') {
      try {
        body = JSON.stringify(await readJson(request));
      } catch {
        return json({ error: '올바른 키 발급 요청이 필요합니다.' }, 400);
      }
    }
    const store = env.KEYS.get(env.KEYS.idFromName('key-store'));
    return store.fetch('https://internal' + url.pathname.slice('/admin'.length), {
      method: request.method,
      headers: { Authorization: 'Bearer ' + bearer(request), 'Content-Type': 'application/json' },
      body,
    });
  }

  if (url.pathname === '/mcp') {
    if (request.method !== 'POST') return new Response(null, { status: 405, headers: { Allow: 'POST' } });
    const token = bearer(request);
    if (token) {
      const store = env.KEYS.get(env.KEYS.idFromName('key-store'));
      const verified = await store.fetch('https://internal/verify', {
        method: 'POST', headers: { Authorization: 'Bearer ' + token },
      });
      if (verified.status === 204) return handleMcp(request);
      if (verified.status !== 401) return json({ error: '키를 확인할 수 없습니다.' }, 503);
    }
    return new Response(null, { status: 401, headers: {
      'WWW-Authenticate': 'Bearer realm="security-insight-mcp"', 'Cache-Control': 'no-store',
    } });
  }
  return json({ error: '경로를 찾을 수 없습니다.' }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      return json({ error: '서비스 요청을 처리할 수 없습니다.' }, 500);
    }
  },
};
