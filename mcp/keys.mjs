const encoder = new TextEncoder();
const decoder = new TextDecoder();
const keyPattern = /^si_([0-9a-f]{24})\.[0-9a-f]{64}$/;
const recordPrefix = 'key:';

export const json = (body, status = 200) => Response.json(body, {
  status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
});

export const bearer = (request) =>
  /^Bearer ([!-~]{1,256})$/i.exec(request.headers.get('Authorization') || '')?.[1];

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
export const randomHex = (length) => hex(crypto.getRandomValues(new Uint8Array(length)));

const digest = async (value) => new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
export function equal(left, right) {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index++) mismatch |= left[index] ^ right[index];
  return mismatch === 0;
}

export async function isAdmin(request, env) {
  const token = bearer(request);
  return Boolean(token && env.ADMIN_TOKEN?.length >= 32 &&
    equal(await digest(token), await digest(env.ADMIN_TOKEN)));
}

const secretBytes = (secret) => Uint8Array.from(secret.match(/../g), (pair) => parseInt(pair, 16));
const encKey = (secret) => {
  if (!/^[0-9a-f]{64}$/i.test(secret || '')) throw new Error('Key encryption is unavailable');
  return crypto.subtle.importKey('raw', secretBytes(secret), 'AES-GCM', false, ['encrypt', 'decrypt']);
};

function publicRecord({ id, label, createdAt, revokedAt }) {
  return { id, label, prefix: 'si_' + id, createdAt, revokedAt };
}

export class KeyStore {
  constructor(state, env) {
    this.storage = state.storage;
    this.env = env;
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/verify' && request.method === 'POST') {
      const token = bearer(request);
      const id = keyPattern.exec(token || '')?.[1];
      const entry = id && await this.storage.get(recordPrefix + id);
      const valid = entry && !entry.revokedAt && equal(await digest(token), entry.digest);
      return new Response(null, { status: valid ? 204 : 401 });
    }
    if (!await isAdmin(request, this.env)) return json({ error: '관리자 인증이 필요합니다.' }, 401);

    if (path === '/keys' && request.method === 'GET') {
      const entries = await this.storage.list({ prefix: recordPrefix });
      const keys = Array.from(entries.values(), publicRecord).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt));
      return json({ keys });
    }
    if (path === '/keys' && request.method === 'POST') {
      const { label } = await request.json().catch(() => ({})) || {};
      if (typeof label !== 'string' || !label.trim() || label.trim().length > 80) {
        return json({ error: '키 이름을 1~80자로 입력하세요.' }, 400);
      }
      const id = randomHex(12);
      const token = 'si_' + id + '.' + randomHex(32);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: encoder.encode(id) },
        await encKey(this.env.KEY_ENCRYPTION_SECRET), encoder.encode(token),
      );
      const entry = { id, label: label.trim(), createdAt: new Date().toISOString(), revokedAt: null,
        digest: await digest(token), iv, ciphertext };
      await this.storage.put(recordPrefix + id, entry);
      return json({ ...publicRecord(entry), key: token }, 201);
    }

    const match = /^\/keys\/([0-9a-f]{24})(\/reveal)?$/.exec(path);
    if (!match) return json({ error: '경로를 찾을 수 없습니다.' }, 404);
    const [, id, reveal] = match;
    const storageKey = recordPrefix + id;
    if (!reveal && request.method === 'DELETE') {
      return this.storage.transaction(async (transaction) => {
        const entry = await transaction.get(storageKey);
        if (!entry) return json({ error: '키를 찾을 수 없습니다.' }, 404);
        if (!entry.revokedAt) {
          const revoked = { ...publicRecord(entry), revokedAt: new Date().toISOString() };
          await transaction.put(storageKey, revoked);
          return json(revoked);
        }
        return json(publicRecord(entry));
      });
    }
    if (reveal && request.method === 'POST') {
      const entry = await this.storage.get(storageKey);
      if (!entry || entry.revokedAt) return json({ error: '활성 키를 찾을 수 없습니다.' }, 404);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: entry.iv, additionalData: encoder.encode(id) },
        await encKey(this.env.KEY_ENCRYPTION_SECRET), entry.ciphertext,
      );
      return json({ key: decoder.decode(plaintext) });
    }
    return json({ error: '지원하지 않는 요청입니다.' }, 405);
  }
}
