const base = 'https://yongseok-mun.github.io/security-insight/';
const cvePattern = '^CVE-[0-9]{4}-[0-9]{4,}$';
const id = { type: 'string', pattern: cvePattern, maxLength: 32 };
const query = { type: 'string', minLength: 1, maxLength: 120 };
const limit = { type: 'integer', minimum: 1, maximum: 25, default: 10 };
const offset = { type: 'integer', minimum: 0, maximum: 2000, default: 0 };
const choice = (...values) => ({ type: 'string', enum: values });
const listing = { limit, offset };
const tools = {};

function add(name, description, properties, handler, required = []) {
  tools[name] = {
    descriptor: { name, description, inputSchema: { type: 'object', properties, required,
      additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true } },
    handler,
  };
}

async function load(file) {
  const response = await fetch(new URL(file, base), {
    cf: { cacheTtl: 60, cacheEverything: true },
    signal: AbortSignal.timeout(10000),
    redirect: 'error',
  });
  if (!response.ok) throw new Error('공개 데이터 조회에 실패했습니다.');
  const data = await response.json();
  if (!data || Array.isArray(data) || typeof data !== 'object') {
    throw new Error('공개 데이터 형식이 올바르지 않습니다.');
  }
  if (file === 'data.json' && (!data.updatedAt || !Array.isArray(data.cves) || !Array.isArray(data.news))) {
    throw new Error('게시본의 필수 데이터가 누락되었습니다.');
  }
  return data;
}

const includes = (value, term) => String(value ?? '').toLowerCase().includes(term);
const matchesCve = (item, term) => [item.id, item.title, item.titleKo, item.product,
  ...(item.cna?.affected ?? []).flatMap(({ vendor, product }) => [vendor, product]),
  ...(item.officialPatches ?? []).map(({ product }) => product),
].some((value) => includes(value, term));
const newest = (a, b) => (b.published ?? '').localeCompare(a.published ?? '');
const epssScore = (item) => typeof item.epss === 'number' ? item.epss : item.epss?.score;
const page = (items, args) => {
  const start = args.offset ?? 0;
  const end = start + (args.limit ?? 10);
  return { total: items.length, nextOffset: end < items.length ? end : null, items: items.slice(start, end) };
};
const fromSnapshot = (data, result) => ({
  updatedAt: data.updatedAt,
  collectionState: data.collection?.state ?? null,
  ...result,
});

add('get_snapshot_status', '현재 데이터 게시 시각, 출처별 상태와 수집 건수를 가져옵니다.', {}, async () => {
  const data = await load('data.json');
  return fromSnapshot(data, { collection: data.collection ?? null, sources: data.sources ?? {},
    cveCount: data.cves.length, newsCount: data.news.length, site: base });
});

add('list_cves', '공개 CVE를 ID·제목·제품명으로 검색합니다. 최신 공개순, KEV 등재순 또는 EPSS 점수순으로 조회합니다.', {
  query, view: choice('all', 'critical', 'kev', 'epss'), scope: choice('current', 'archive'),
  impactArea: choice('kernel', 'system', 'web-service', 'web-app', 'appliance',
    'database', 'cloud-virtualization', 'library-runtime', 'unclassified'), ...listing,
}, async (args) => {
  const data = await load('data.json');
  const archived = args.scope === 'archive';
  const source = archived ? Object.values(await load('cve-archive.json')) : data.cves;
  let items = source.filter((item) => !args.query || matchesCve(item, args.query.toLowerCase()));
  if (args.impactArea) items = items.filter((item) => {
    const areas = item.impactArea?.areas ?? [];
    return args.impactArea === 'unclassified' ? !areas.length : areas.includes(args.impactArea);
  });
  if (args.view === 'critical') items = items.filter((item) => item.cvss >= 9);
  if (args.view === 'kev') {
    items = items.filter((item) => item.kev === true)
      .sort((a, b) => (b.kevDate ?? '').localeCompare(a.kevDate ?? '') || newest(a, b));
  } else if (args.view === 'epss') {
    items = items.filter((item) => Number.isFinite(epssScore(item)))
      .sort((a, b) => epssScore(b) - epssScore(a) || newest(a, b));
  } else {
    items.sort(newest);
  }
  const summaries = items.map(({ id, title, product, published, cvss, cvssSource, epss, kev, kevDate,
    archivedAt, impactArea }) => ({ id, title, product, published, cvss, cvssSource, epss, kev, kevDate, archivedAt,
    impactArea: impactArea ?? { primary: 'unclassified', areas: [], evidence: {} } }));
  return fromSnapshot(data, { scope: archived ? 'archive' : 'current', ...page(summaries, args) });
});

add('get_cve', '공개 CVE 상세와 관련 변경 이력을 가져옵니다. 현재 목록에 없으면 아카이브를 조회합니다.',
  { id }, async (args) => {
    const data = await load('data.json');
    const current = data.cves.find((item) => item.id === args.id);
    const archived = current ? null : (await load('cve-archive.json'))[args.id] ?? null;
    return fromSnapshot(data, { cve: current ?? archived, scope: current ? 'current' : archived ? 'archive' : null,
      history: (data.history ?? []).filter((item) => item.id === args.id) });
  }, ['id']);

add('list_news', '공개 기사, 국내 동향, KISA 보안공지 및 다크웹 관련 공개 보도를 검색합니다.', {
  query, category: choice('all', 'korea', 'kisa', 'advisory', 'dark'), ...listing,
}, async (args) => {
  const data = await load('data.json');
  const items = data.news.filter((item) => {
    if (args.category === 'korea' && !item.korea) return false;
    if (args.category === 'kisa' && !item.feed?.startsWith('KISA 보호나라')) return false;
    if (args.category === 'advisory' && item.kind !== 'advisory') return false;
    if (args.category === 'dark' && !item.dark) return false;
    const term = args.query?.toLowerCase();
    return !term || [item.title, item.publisher, item.feed, ...(item.cves ?? [])].some((value) => includes(value, term));
  });
  return fromSnapshot(data, page(items, args));
});

add('list_changes', '게시본에 기록된 신규 CVE, KEV 등재, 패치·완화 변경 이력을 조회합니다.', {
  type: choice('published', 'kev', 'remediation'), id, ...listing,
}, async (args) => {
  const data = await load('data.json');
  const items = (data.history ?? []).filter((item) =>
    (!args.id || item.id === args.id) && (!args.type || item.type === args.type));
  return fromSnapshot(data, page(items, args));
});

add('get_debian_packages', 'CVE에 연결된 Debian Security Tracker 공개 패키지 정보를 가져옵니다.', { id },
  async (args) => {
    const data = await load('data.json');
    const packages = await load('debian-packages.json');
    return fromSnapshot(data, { id: args.id, packages: packages[args.id] ?? null });
  }, ['id']);

export const listTools = () => Object.values(tools).map((tool) => tool.descriptor);

export function resolveTool(name, args) {
  if (typeof name !== 'string' || !Object.hasOwn(tools, name) ||
      !args || Array.isArray(args) || typeof args !== 'object') return null;
  const { descriptor, handler } = tools[name];
  const { properties, required } = descriptor.inputSchema;
  if (required.some((name) => !Object.hasOwn(args, name))) return null;
  for (const [name, value] of Object.entries(args)) {
    if (!Object.hasOwn(properties, name)) return null;
    const schema = properties[name];
    if (schema.type === 'integer') {
      if (!Number.isInteger(value) || value < schema.minimum || value > schema.maximum) return null;
    } else if (typeof value !== 'string' || value.length < (schema.minLength ?? 0) ||
        value.length > (schema.maxLength ?? Infinity) || (schema.enum && !schema.enum.includes(value)) ||
        (schema.pattern && !new RegExp(schema.pattern).test(value))) return null;
  }
  return handler;
}
