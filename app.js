'use strict';

// Compact outline icons adapted from Lucide (ISC license).
const icons = {
  shield: '<path d="M12 22s7-4 7-10V5l-7-3-7 3v7c0 6 7 10 7 10Z"/><path d="m9 12 2 2 4-4"/>',
  news: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M11 8h6m-6 4h6m-10 4h10M7 8v4"/>',
  flame: '<path d="M12 22a7 7 0 0 0 7-7c0-4-3-7-6-10 0 4-2 5-3 6 0-2-1-3-2-4-2 3-3 5-3 8a7 7 0 0 0 7 7Z"/>',
  chart: '<path d="M4 20v-4m5 4v-8m5 8V8m5 12V4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a7 7 0 0 1 7-7h2a7 7 0 0 1 7 7v2Z"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>',
  link: '<path d="M10 13a4 4 0 0 0 6 0l4-4a4 4 0 0 0-6-6l-2 2m2 6a4 4 0 0 0-6 0l-4 4a4 4 0 0 0 6 6l2-2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  doc: '<path d="M6 3h8l4 4v14H6Z M10 11h4m-4 4h4"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name]}</svg>`;
const $ = (selector) => document.querySelector(selector);

document.querySelectorAll('[data-icon]').forEach((node) => {
  node.innerHTML = icon(node.dataset.icon);
});

const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

const dateFormat = new Intl.DateTimeFormat('ko-KR', {
  timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  hourCycle: 'h23',
});
const date = (value) => value ? `${dateFormat.format(new Date(value))} KST` : '시각 미제공';
const cvss = (item) => Number.isFinite(item.cvss) ? item.cvss.toFixed(1) : '—';
const epss = (item) => item.epss ? `${item.epss.score}%` : '—';
const kev = (item) => item.kev === true ? '등재' : item.kev === false ? '미등재' : '미확인';
const labels = {home:'보안 브리핑', news:'보안 뉴스', issues:'핵심 이슈', korea:'국내 동향', cve:'주요취약점공지', dark:'다크웹 보도'};
const comparePriority = (a, b) => Number(b.kev === true) - Number(a.kev === true)
  || (b.cvss ?? -1) - (a.cvss ?? -1) || (b.epss?.score ?? -1) - (a.epss?.score ?? -1)
  || (b.published || '').localeCompare(a.published || '');
const publicUrl = (address) => {
  try {
    const parsed = new URL(address);
    if (['https:', 'http:'].includes(parsed.protocol) && !parsed.username && !parsed.password) {
      return parsed.href;
    }
  } catch { /* The upstream record may have no URL. */ }
  return '';
};
const link = (address, label) => {
  const url = publicUrl(address);
  return url ? `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${escape(label)} ↗</a>` : '';
};

const requestedCve = new URL(location.href).searchParams.get('cve')?.trim().toUpperCase();
const incomingCve = /^CVE-\d{4}-\d{4,}$/.test(requestedCve || '') ? requestedCve : null;
const cveUrl = (id) => {
  const url = new URL(location.pathname, location.origin);
  url.searchParams.set('cve', id);
  return url.href;
};
let data = {cves:[], news:[], sources:{}};
let selected;
let archiveResults = [];
let archiveQuery = '';
const comparisonWork = new Map();
let archivePromise;
let priorities = [];
let priorityReasons = new Map();
let pendingSnapshot;
let newsMode = 'recent';
let mailDraft;
let cveMailContext;
let myWorkFilter = 'active';
let prioritySelection = null;
let loading = false;
let clockTimer;
let page = 'home';
let view = 'latest';
const newest = (a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0)
  || a.id.localeCompare(b.id);

const preferenceKey = 'security-insight.preferences.v1';
const reviewLabels = {unreviewed:'미확인', investigate:'영향 확인 필요', done:'조치 완료', recheck:'재검토 필요'};
let canSavePreferences = true;

function readPreferences() {
  try {
    const stored = JSON.parse(localStorage.getItem(preferenceKey) || '{}');
    return {
      products: Array.isArray(stored.products) ? stored.products.filter((name) => typeof name === 'string') : [],
      reviews: stored.reviews && typeof stored.reviews === 'object' ? stored.reviews : {},
    };
  } catch {
    return {products:[], reviews:{}};
  }
}

const preferences = readPreferences();

function savePreferences() {
  try {
    localStorage.setItem(preferenceKey, JSON.stringify(preferences));
    canSavePreferences = true;
  } catch {
    canSavePreferences = false;
  }
}

const normalizeProduct = (value) => String(value || '').normalize('NFKC').toLowerCase()
  .replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const productAliases = {
  'linux kernel':['linux kernel','kernel linux','linux linux'],
  'nginx':['nginx','nginx plus','nginx ingress controller'],
  'fortinet':['fortinet','fortios','fortiproxy','fortimanager','fortianalyzer','forticlient','fortiweb'],
  'openssl':['openssl','open ssl'],
};
const matchesProduct = (item, product) => {
  const name = normalizeProduct(product);
  const names = Object.hasOwn(productAliases, name) ? productAliases[name] : [name];
  const metadata = (item.cna?.affected || []).flatMap(({vendor, product: affected}) =>
    [vendor, affected, [vendor, affected].filter(Boolean).join(' ')]);
  const searchable = [item.product, ...metadata].filter(Boolean);
  const labels = (searchable.length ? searchable : [item.title]).map((value) => ` ${normalizeProduct(value)} `);
  return names.some((alias) => alias && labels.some((label) => label.includes(` ${alias} `)));
};
const watched = (item) => preferences.products.some((product) => matchesProduct(item, product));

// Keep the existing snapshot order for completion records saved by earlier releases.
const remediationFields = ['패치 버전', '해결책', '완화책', 'CISA 조치 권고', '영향 버전·조건', 'Debian 수정 패키지', '공식 제품별 패치 기준'];

function remediationValues(item) {
  return [
    [...new Set([...(item.fixes || []), ...(item.describedFixes || [])])].sort(),
    [...new Set(item.cna?.solutions || [])].sort(),
    [...new Set(item.cna?.workarounds || [])].sort(),
    item.requiredAction || '',
    item.impactScope || [],
    (item.debianPackages || []).map(({suite, package:pkg, fixed}) => `${suite} / ${pkg} · ${fixed}`).sort(),
    [...new Set((item.officialPatches || []).map(({product, affected, fixed, url}) =>
      `${product} · 영향 ${affected} → 해결 ${fixed} · ${url}`))].sort(),
  ];
}

const remediationFingerprint = (item) => JSON.stringify(remediationValues(item));

function remediationSinceReview(item, review) {
  const reviewedThrough = Date.parse(review.reviewedThrough);
  return (data.history || []).filter((event) => event.id === item.id && event.type === 'remediation'
    && Date.parse(event.at) > reviewedThrough);
}

function reviewState(item) {
  const review = preferences.reviews[item.id];
  if (review?.state === 'investigate') return 'investigate';
  if (review?.state !== 'done') return 'unreviewed';
  return remediationHasChanges(item, review) ? 'recheck' : 'done';
}

function completedRemediation(review) {
  try {
    const snapshot = JSON.parse(review.fingerprint);
    if (Array.isArray(snapshot) && [4, 6, remediationFields.length].includes(snapshot.length)
      && snapshot.every((values, index) => index === 3 ? typeof values === 'string'
        : Array.isArray(values) && values.every((value) => typeof value === 'string'))) return snapshot;
  } catch { /* Some stored reviews may be missing a readable snapshot. */ }
  return null;
}

function remediationHasChanges(item, review) {
  const saved = completedRemediation(review);
  return !saved || JSON.stringify(saved) !== JSON.stringify(remediationValues(item).slice(0, saved.length))
    || (saved.length < remediationFields.length && Boolean(item.officialPatches?.length))
    || remediationSinceReview(item, review).length > 0;
}

function reviewBadge(item) {
  const state = reviewState(item);
  return `<span class="pill review-badge review-${state}">${reviewLabels[state]}</span>`;
}

function cveSearchMatch(item, query) {
  const terms = normalizeProduct(query).split(' ').filter(Boolean);
  const matches = (values) => {
    const text = normalizeProduct(values.filter(Boolean).join(' '));
    return terms.every((term) => text.includes(term));
  };
  if (matches([item.id, item.title, item.product, ...(item.fixes || []), item.description])) return '';
  if (matches((item.officialPatches || []).map(({product}) => product))) return 'KISA 제품명 일치';
  if (matches((item.cna?.affected || []).flatMap(({vendor, product}) => [vendor, product]))) return 'CNA 제품명 일치';
  if (matches([item.titleKo, item.descriptionKo])) return '한국어 설명 일치';
  if (matchesProduct(item, query)) return '제품명·별칭 일치';
  return null;
}

function rowsForFilters() {
  const query = $('#query').value.trim();
  const product = $('#product').value;
  const include = (item) => cveSearchMatch(item, query) !== null
    && (!product || item.product === product)
    && (view !== 'watch' || watched(item))
    && (view !== 'recheck' || reviewState(item) === 'recheck')
    && (view !== 'kev' || item.kev === true)
    && (view !== 'critical' || item.cvss >= 9)
    && (view !== 'epss' || item.epss != null);
  const rows = data.cves.filter(include);
  const results = rows.length || query !== archiveQuery ? rows : archiveResults.filter(include);
  if (view === 'epss') return results.sort((a, b) => b.epss.score - a.epss.score || newest(a, b));
  if (view === 'kev') return results.sort((a, b) => (b.kevDate || '').localeCompare(a.kevDate || '') || newest(a, b));
  return results.sort(newest);
}

const koreaDay = new Intl.DateTimeFormat('sv-SE', {
  timeZone:'Asia/Seoul', year:'numeric', month:'2-digit', day:'2-digit',
});

function publicationDate(value) {
  const stamp = Date.parse(value);
  if (!Number.isFinite(stamp)) return '';
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : koreaDay.format(stamp);
}

// Product families whose core runtime, OS or infrastructure role can span multiple services.
const widespreadProducts = [
  [/^(?:oracle )?(?:java se|graalvm(?: for jdk| enterprise edition)?|openjdk|jdk|hotspot)$/, 'Java 런타임·JDK'],
  [/^(?:(?:linux )?linux kernel|linux linux|linux)$/, 'Linux 커널'],
  [/^(?:microsoft )?windows(?: server| (?:10|11))?(?: [0-9][a-z0-9 ]*)?$/, 'Windows 운영체제'],
  [/^(?:(?:google )?chrome|(?:google )?chromium|mozilla firefox|firefox)$/, '웹 브라우저'],
  [/^(?:apache http server|apache httpd|nginx(?: open source| plus)?|openssl|open ssl)$/, '웹·TLS 공통 인프라'],
  [/^(?:node js|nodejs|python|cpython|kubernetes)$/, '런타임·컨테이너 공통 인프라'],
];

function briefingReach(item) {
  const products = [item.product, ...(item.cna?.affected || []).map(({product}) => product)].map(normalizeProduct);
  return widespreadProducts.find(([pattern]) => products.some((product) => pattern.test(product)))?.[1] || '';
}

const briefingConditions = {
  'CVE-2026-114938': {
    alias:'Java4Shell',
    environment:'영향받는 Java 런타임에서 x86-64 AVX-512 VBMI 경로를 사용하고, 공격자 입력이 Base64 디코딩에 도달하는 환경',
    firstCheck:'서비스·컨테이너의 번들 JDK 버전과 CPU의 AVX-512 VBMI 지원 여부를 확인하세요.',
    sources:[
      ['CISA 긴급 패치 권고', 'https://content.govdelivery.com/accounts/USDHSCISA/bulletins/4332a87'],
      ['CSA 제품·악용 조건 안내', 'https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-166/'],
      ['Sophos CPU·공격 전제조건', 'https://www.sophos.com/en-us/security-advisories/sophos-sa-20261118-java4shell'],
    ],
  },
};

function briefingPriority(snapshot, isWatched = watched) {
  const asOf = Date.parse(snapshot.updatedAt);
  const endDay = Date.parse(koreaDay.format(asOf));
  const recent = (value, days = 7) => {
    const stamp = Date.parse(value);
    if (!Number.isFinite(stamp)) return false;
    const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value);
    const day = Date.parse(publicationDate(value));
    return (dateOnly || stamp <= asOf) && day <= endDay && endDay - day < days * 86400000;
  };
  const changed = new Map();
  for (const event of snapshot.history || []) {
    if (event.type !== 'remediation' || !recent(event.at)) continue;
    const stamp = Date.parse(event.at);
    changed.set(event.id, Math.max(changed.get(event.id) || 0, stamp));
  }
  const ranked = snapshot.cves.map((item) => {
    const newKev = item.kev === true && recent(item.kevDate);
    const watchedProduct = isWatched(item);
    const watchChange = watchedProduct ? changed.get(item.id) : undefined;
    const network = cvssMetrics(item).AV === 'N';
    const reach = briefingReach(item);
    const coverage = item.briefingCoverage;
    const covered = recent(coverage?.latest, 4) && (coverage.official || coverage.publishers >= 2);
    const newHighRisk = network && item.cvss >= 9 && recent(item.published, 2);
    const broadImpact = Boolean(reach && network && item.cvss >= 7
      && (recent(item.published, 2) || (covered && coverage.official)));
    const spotlight = newHighRisk || broadImpact;
    const rank = newKev ? 0 : watchChange ? 1 : spotlight ? 2 : watchedProduct && network ? 3 : 4;
    const reasons = [
      newKev ? `최근 KEV 등재 (${item.kevDate.slice(5, 10).replace('-', '.')})` : '',
      newHighRisk ? `신규 공개 고위험 (${publicationDate(item.published)})` : '',
      reach ? `범용 구성요소 · ${reach}` : '',
      covered ? [coverage.official ? '공공기관 공지' : '', `최근 보도 ${coverage.publishers}개 매체`].filter(Boolean).join(' · ') : '',
      watchChange ? '관심 제품의 조치 정보 변경' : watchedProduct ? '관심 제품' : '',
    ].filter(Boolean);
    if (rank === 4) {
      reasons.unshift(item.kev === true ? '기존 KEV 등재' : '공개 위험 지표 기준');
    }
    const sortDate = newKev ? Date.parse(item.kevDate) : watchChange || 0;
    return {item, rank, sortDate, watchChange, spotlight, broadImpact, covered, reason:reasons.join(' · ')};
  }).sort((a, b) => a.rank - b.rank || b.sortDate - a.sortDate
    || (a.rank === 2 ? Number(b.broadImpact) - Number(a.broadImpact)
      || Number(b.covered) - Number(a.covered) : 0)
    || Number(b.item.kev === true) - Number(a.item.kev === true)
    || (b.item.cvss ?? -1) - (a.item.cvss ?? -1)
    || (b.item.epssStatus !== 'stale' ? b.item.epss?.score ?? -1 : -1)
      - (a.item.epssStatus !== 'stale' ? a.item.epss?.score ?? -1 : -1)
    || newest(a.item, b.item));
  const top = ranked.slice(0, 3);
  // Keep the lead item and reserve space for a watched change and a qualifying risk or broad impact.
  for (const key of ['watchChange', ranked.some((entry) => entry.broadImpact) ? 'broadImpact' : 'spotlight']) {
    if (top.some((entry) => entry[key])) continue;
    const candidate = ranked.find((entry) => entry[key]);
    const replace = top.findLastIndex((entry, index) => index > 0 && !entry.watchChange
      && (key === 'broadImpact' || !entry.spotlight));
    if (candidate && replace !== -1) top[replace] = candidate;
  }
  return ranked.filter((entry) => top.includes(entry));
}

function cveHeading(item) {
  const title = item.titleKo || item.title || item.id;
  const alias = briefingConditions[item.id]?.alias;
  return alias && !title.toLowerCase().includes(alias.toLowerCase()) ? `${alias} · ${title}` : title;
}

function firstAssetCheck(item) {
  const curated = briefingConditions[item.id]?.firstCheck;
  if (curated) return curated;
  if ((item.cna?.affected || []).some((product) => checkpointHotfixRanges(product).length)) {
    return '설치 릴리스와 Jumbo Hotfix Take를 함께 확인하세요.';
  }
  const metrics = cvssMetrics(item);
  if (metrics.AV === 'N') return '영향 버전과 취약 기능의 네트워크 접근 경로를 확인하세요.';
  if (metrics.AV === 'L') return '영향 버전과 로컬 계정의 접근 권한을 확인하세요.';
  return '공지를 기준으로 설치 버전과 영향받는 기능의 사용 여부를 확인하세요.';
}

function updatePriorities() {
  const ranked = briefingPriority(data);
  priorities = ranked.map(({item}) => item);
  priorityReasons = new Map(ranked.map(({item, reason}) => [item.id, reason]));
}

function renderPriority() {
  const panel = $('#priority-inspector');
  rememberComparisons('#priority-inspector');
  const item = priorities.find((entry) => entry.id === prioritySelection);
  prioritySelection = item?.id || null;
  panel.hidden = true;
  $('#priority').append(panel);
  $('#priority').hidden = page !== 'home' || priorities.length === 0;
  const asOf = $('#priority-as-of');
  asOf.hidden = !data.updatedAt;
  if (data.updatedAt) {
    const time = asOf.querySelector('time');
    time.dateTime = data.updatedAt;
    time.textContent = date(data.updatedAt);
  }
  $('#priority-list').innerHTML = priorities.map((entry) => `
    <li><button type="button" class="priority-row" data-cve="${escape(entry.id)}"
      aria-expanded="${entry === item}" aria-controls="priority-inspector">
      <span class="priority-copy">
        <span class="priority-id">${escape(entry.id)}</span><strong>${escape(cveHeading(entry))}</strong>
        <span class="priority-line priority-reason"><b>선정 이유</b> ${escape(priorityReasons.get(entry.id))}</span>
        <span class="priority-line priority-check"><b>첫 점검</b> ${escape(firstAssetCheck(entry))}</span>
      </span>
      <span class="cve-meta">
        ${entry.kev === true ? '<span class="pill kev">KEV</span>' : ''}
        <span class="pill">CVSS ${Number.isFinite(entry.cvss) ? cvss(entry) : '미확인'}</span>
        <span class="pill">EPSS ${entry.epss ? epss(entry) : '미확인'}${entry.epssStatus === 'stale' ? ' · 이전' : ''}</span>
      </span>
      <span class="priority-detail">${entry === item ? '상세 닫기' : '상세 보기'} <span aria-hidden="true">⌄</span></span>
    </button></li>`).join('');
  if (item) {
    renderInspector(panel, item);
    $('#priority-list [aria-expanded="true"]').after(panel);
    panel.hidden = false;
    attachComparisons('#priority-inspector', item);
  }
}

// The Pages workflow starts at minute 17 on every even UTC hour.
function updateClock(stamp) {
  clearInterval(clockTimer);
  const collected = new Date(stamp);
  const next = new Date(collected);
  next.setUTCHours(Math.floor(next.getUTCHours() / 2) * 2, 17, 0, 0);
  if (next <= collected) next.setUTCHours(next.getUTCHours() + 2);
  const morning = new Date(collected);
  morning.setUTCHours(21, 17, 0, 0);
  if (morning <= collected) morning.setUTCDate(morning.getUTCDate() + 1);
  if (morning < next) next.setTime(morning.getTime());
  $('#next-update').dateTime = next.toISOString();
  $('#next-update').textContent = date(next);
  const tick = () => {
    const seconds = Math.max(0, Math.ceil((next - Date.now()) / 1000));
    const parts = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60];
    const progress = Math.max(0, Math.min(100, (Date.now() - collected) / (next - collected) * 100));
    $('#update-progress').style.width = `${progress}%`;
    $('#countdown').textContent = seconds
      ? parts.map((part) => String(part).padStart(2, '0')).join(':')
      : '갱신 대기';
  };
  tick();
  clockTimer = setInterval(tick, 1000);
}

const wideCveLayout = matchMedia('(min-width: 960px)');

function placeCveInspector() {
  const inspector = $('#inspector');
  const row = $('#rows [aria-expanded="true"]');
  const dock = $('#inspector-dock');
  const destination = row && !wideCveLayout.matches ? row.parentElement : dock;
  if (inspector.parentElement === destination) return;
  const focus = inspector.contains(document.activeElement) ? document.activeElement : null;
  destination.append(inspector);
  focus?.focus({preventScroll:true});
}

wideCveLayout.addEventListener('change', placeCveInspector);

function renderRows() {
  const records = rowsForFilters();
  if (!records.includes(selected)) selected = null;
  const inspector = $('#inspector');
  rememberComparisons('#inspector');
  inspector.hidden = true;
  $('#inspector-dock').append(inspector);
  $('#cve-workbench').classList.toggle('has-selection', Boolean(selected));

  $('#rows').innerHTML = records.map((item) => {
    const active = item === selected;
    const published = publicationDate(item.published);
    const sourceMatch = cveSearchMatch(item, $('#query').value);
    const severity = item.cvss >= 9 ? 'critical' : item.cvss >= 7 ? 'high' : item.cvss >= 4 ? 'medium' : '';
    return `<li>
      <button class="cve-row" type="button" data-id="${escape(item.id)}"
        aria-expanded="${active}" ${active ? 'aria-controls="inspector"' : ''}>
        <span class="cve-identity">
          <span class="cve-id">${escape(item.id)}</span>
          <span class="cve-published">발표일 ${published ? `<time datetime="${escape(item.published)}">${escape(published)}</time>` : '미확인'}</span>
        </span>
        <span class="cve-description"><strong>${escape(cveHeading(item))}</strong>${item.product ? `<small>${escape(item.product)}</small>` : ''}</span>
        <span class="cve-meta">
          ${sourceMatch ? `<span class="pill">${escape(sourceMatch)}</span>` : ''}
          ${archiveResults.includes(item) ? '<span class="pill">보관 자료</span>' : ''}
          <span class="pill ${severity}">CVSS ${Number.isFinite(item.cvss) ? cvss(item) : '미확인'}</span>
          ${item.kev === true ? '<span class="pill kev">KEV</span>' : ''}
          ${item.fixes.length ? '<span class="pill fix">수정 버전</span>' : ''}
          ${reviewState(item) !== 'unreviewed' ? reviewBadge(item) : ''}
          ${view === 'epss' ? `<span class="pill">EPSS ${epss(item)}</span>` : ''}
        </span>
      </button>
    </li>`;
  }).join('') || `<li class="empty">조건에 맞는 CVE가 없습니다.
    ${$('#query').value.trim() && $('#query').value.trim() !== archiveQuery ?
      '<button type="button" class="outline" data-search-archive>보관 자료 검색</button>' : ''}</li>`;

  $('#count').textContent = `총 ${records.length}건`;
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.view === view));
  });
  if (selected) {
    const changed = inspector.dataset.comparisonCve !== selected.id;
    renderInspector();
    placeCveInspector();
    inspector.hidden = false;
    if (changed) inspector.scrollTop = 0;
    attachComparisons('#inspector', selected);
  }
}

function evidence(item) {
  const sources = [
    ['CVE Program · CNA 원문', `https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`,
      item.cna?.provider ? `등록 기관: ${item.cna.provider}` : 'CVE 레코드에서 제품·버전·해결책 확인'],
    ['cve.now', item.url, '피드에 게시된 제목·발행일·제품 정보'],
    ['NVD', `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`, item.nvd
      ? (item.nvdStatus || '레코드 수집') : '이번 수집 범위에서 레코드 미확인'],
    ['FIRST EPSS', `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(item.id)}`,
      item.epss ? `점수 기준일 ${item.epss.date} · 향후 30일 악용 가능성 추정치` : '수집된 점수 없음'],
    ['CISA KEV', `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`,
      item.kevDate ? `등재일 ${item.kevDate}` : `카탈로그 상태 ${kev(item)}`],
  ];
  return sources.filter(([name]) => name !== 'cve.now' || item.origin !== 'CISA KEV').map(([name, address, note]) => `<details><summary>${icon('doc')}${name}</summary><p>${escape(note)} · ${link(address, '출처 열기')}</p></details>`).join('')
    + [...new Set([...(item.cna?.references || []), ...item.references])].map((address) => `<p class="evidence-link">${link(address, '벤더 공지·패치')}</p>`).join('')
    + item.notices.map((notice) => `<p class="evidence-link">${link(notice.url, 'KISA · ' + notice.title)}</p>`).join('')
    + (briefingConditions[item.id]?.sources || []).map(([label, address]) =>
      `<p class="evidence-link">${link(address, label)}</p>`).join('');
}

const versionStates = {affected:'영향받음', unaffected:'영향 없음', unknown:'영향 여부 미확인'};

const versionNames = new Map([['all','모든 버전'], ['any','모든 버전'], ['previous versions','이전 버전'], ['n/a','버전 미기재']]);

function versionLabel(entry) {
  const version = versionNames.get(String(entry.version).toLowerCase()) || entry.version;
  const lower = version === '0' && (entry.lessThan || entry.lessThanOrEqual)
    ? '최초 버전부터' : `${version} 이상`;
  const range = entry.lessThan ? `${lower} · ${entry.lessThan} 미만`
    : entry.lessThanOrEqual ? `${lower} · ${entry.lessThanOrEqual} 이하` : version;
  const transitions = (entry.changes || []).map((change) =>
    `${change.at}부터 ${versionStates[change.status] || '상태 확인 필요'}`);
  return [`${versionStates[entry.status] || '미확인'}: ${range}`, ...transitions].join(' · ');
}

function cvssMetrics(item) {
  if (!/^CVSS:(3\.[01]|4\.0)\//.test(item.vector || '')) return {};
  return Object.fromEntries(item.vector.split('/').slice(1).map((part) => part.split(':')));
}

function attackConditions(item) {
  const values = cvssMetrics(item);
  const mapping = [
    ['AV', '접근 경로', {N:'네트워크', A:'인접 네트워크', L:'로컬', P:'물리 접근'}],
    ['PR', '필요 권한', {N:'없음', L:'낮은 권한', H:'높은 권한'}],
    ['UI', '사용자 상호작용', {N:'없음', R:'필요', P:'수동 상호작용', A:'능동 상호작용'}],
    ['AT', '추가 공격 요구사항', {N:'없음', P:'있음'}],
  ];
  return mapping.flatMap(([key, name, options]) => options[values[key]] ? [`${name} · ${options[values[key]]}`] : []);
}

const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function parseSemver(value) {
  const match = semverPattern.exec(value);
  if (!match) return null;
  const prerelease = match[4]?.split('.') || [];
  if (prerelease.some((part) => /^0\d+$/.test(part))) return null;
  return {core:match.slice(1, 4).map(BigInt), prerelease};
}

const compare = (a, b) => a === b ? 0 : a < b ? -1 : 1;
const numericIdentifier = /^\d+$/;

function compareSemver(a, b) {
  for (let index = 0; index < 3; index++) {
    const order = compare(a.core[index], b.core[index]);
    if (order) return order;
  }
  if (!a.prerelease.length || !b.prerelease.length) {
    return compare(!a.prerelease.length, !b.prerelease.length);
  }
  for (let index = 0; index < Math.min(a.prerelease.length, b.prerelease.length); index++) {
    const left = a.prerelease[index];
    const right = b.prerelease[index];
    const leftNumeric = numericIdentifier.test(left);
    const rightNumeric = numericIdentifier.test(right);
    const order = leftNumeric && rightNumeric ? compare(BigInt(left), BigInt(right))
      : leftNumeric !== rightNumeric ? compare(rightNumeric, leftNumeric) : compare(left, right);
    if (order) return order;
  }
  return compare(a.prerelease.length, b.prerelease.length);
}

function compareSemverLimit(version, limit) {
  if (limit === '*') return -1;
  if (/^(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?\.\*$/.test(limit)) {
    const prefix = limit.split('.').slice(0, -1);
    for (let index = 0; index < prefix.length; index++) {
      const order = compare(version.core[index], BigInt(prefix[index]));
      if (order) return order;
    }
    return -1;
  }
  const boundary = parseSemver(limit);
  return boundary ? compareSemver(version, boundary) : null;
}

function evaluateVersionEntry(entry, rawVersion, semver) {
  const strictLimit = entry.lessThan;
  const inclusiveLimit = entry.lessThanOrEqual;
  if (!strictLimit && !inclusiveLimit) {
    if (!entry.version || /^(all|any|n\/a|unknown|unspecified)$/i.test(entry.version)
      || entry.version.includes('*') || entry.changes?.length) return 'unknown';
    if (entry.versionType === 'semver') {
      const exact = parseSemver(entry.version);
      if (!exact || !semver) return 'unknown';
      return compareSemver(semver, exact) === 0 ? entry.status : 'outside';
    }
    if (entry.version === rawVersion && /^[vV]?\d[0-9A-Za-z.+:_-]*$/.test(rawVersion)) return entry.status;
    return semver && parseSemver(entry.version) && !entry.versionType ? 'outside' : 'unsupported';
  }
  if ((strictLimit && inclusiveLimit) || entry.versionType !== 'semver' || !semver) {
    return 'unsupported';
  }

  const lower = entry.version === '0' ? null : parseSemver(entry.version);
  const upperOrder = compareSemverLimit(semver, strictLimit || inclusiveLimit);
  if ((!lower && entry.version !== '0') || upperOrder === null) return 'unsupported';
  if ((lower && compareSemver(semver, lower) < 0) || upperOrder > 0
    || (strictLimit && upperOrder === 0)) return 'outside';

  const changes = (entry.changes || []).map((change) => ({...change, parsed:parseSemver(change.at)}));
  if (changes.some((change) => !change.parsed)) return 'unsupported';
  changes.sort((a, b) => compareSemver(a.parsed, b.parsed));
  let lastChange;
  for (const change of changes) {
    if (compareSemver(semver, change.parsed) < 0) break;
    if (lastChange && compareSemver(lastChange.parsed, change.parsed) === 0
      && lastChange.status !== change.status) return 'unknown';
    lastChange = change;
  }
  return lastChange?.status || entry.status;
}

function evaluateInstalledVersion(product, version) {
  const semver = parseSemver(version);
  const applicable = (product.versions || [])
    .map((entry) => ({entry, status:evaluateVersionEntry(entry, version, semver)}))
    .filter(({status}) => status !== 'outside');
  if (applicable.some(({status}) => status === 'unsupported')) {
    return {status:'unknown', reason:'CNA 범위에 자동 비교를 지원하지 않는 버전 형식이 있습니다.'};
  }
  if (applicable.some(({status}) => !['affected', 'unaffected'].includes(status))
    || new Set(applicable.map(({status}) => status)).size > 1) {
    return {status:'unknown', reason:'입력 버전에 해당하는 공지의 상태가 미확인이거나 서로 다릅니다.'};
  }
  if (applicable.length) return {status:applicable[0].status, reason:versionLabel(applicable[0].entry)};
  if (semver && product.versions?.length && ['affected', 'unaffected'].includes(product.defaultStatus)) {
    return {status:product.defaultStatus, reason:'CNA 레코드의 목록 외 버전 기본 상태를 적용했습니다.'};
  }
  return {status:'unknown', reason:'입력 버전의 상태를 구조화된 공지에서 확인할 수 없습니다.'};
}

function compareProductLabel(product, fallback) {
  const name = [product.vendor, product.product].filter(Boolean).join(' ') || fallback || '제품명 미확인';
  return [name, ...(product.platforms || []), ...(product.modules || [])].join(' · ');
}

const debianSuites = {bullseye:'Debian 11 (bullseye)', bookworm:'Debian 12 (bookworm)', trixie:'Debian 13 (trixie)'};
const debianRecordUrl = (item) => `https://security-tracker.debian.org/tracker/${encodeURIComponent(item.id)}`;

function debianVersionParts(value) {
  const match = /^(?:(\d+):)?([0-9][A-Za-z0-9.+:~\-]*)$/.exec(value);
  if (!match || (!match[1] && match[2].includes(':'))) return null;
  const lastDash = match[2].lastIndexOf('-');
  if (lastDash < 0) return [BigInt(match[1] || 0), match[2], '0'];
  const revision = match[2].slice(lastDash + 1);
  if (!/^[A-Za-z0-9+.~]+$/.test(revision)) return null;
  return [BigInt(match[1] || 0), match[2].slice(0, lastDash), revision];
}

function compareDebianSegment(left, right) {
  const digit = (char) => Boolean(char && /[0-9]/.test(char));
  const order = (char) => {
    if (char === '~') return -1;
    if (!char || digit(char)) return 0;
    return char.charCodeAt(0) + (/[A-Za-z]/.test(char) ? 0 : 256);
  };
  let a = 0, b = 0;
  while (a < left.length || b < right.length) {
    while ((left[a] && !digit(left[a])) || (right[b] && !digit(right[b]))) {
      const result = compare(order(left[a]), order(right[b]));
      if (result) return result;
      a++;
      b++;
    }
    const aStart = a, bStart = b;
    while (digit(left[a])) a++;
    while (digit(right[b])) b++;
    const number = compare(BigInt(left.slice(aStart, a) || 0), BigInt(right.slice(bStart, b) || 0));
    if (number) return number;
  }
  return 0;
}

function compareDebianVersions(installed, fixed) {
  const left = debianVersionParts(installed), right = debianVersionParts(fixed);
  if (!left || !right) return null;
  return compare(left[0], right[0]) || compareDebianSegment(left[1], right[1]) || compareDebianSegment(left[2], right[2]);
}

function debianPackageCheck(item) {
  const rows = item.debianPackages || [];
  return `<details class="version-check">
    <summary>Debian 패키지·백포트 대조</summary>
    ${rows.length ? `<form data-debian-check>
      <p class="version-hint">Debian 공식 패키지의 소스 이름과 소스 버전을 입력하세요. 자체 빌드와 타 배포판은 해당 공급사 공지를 확인하세요.</p>
      <pre class="debian-command"><code>dpkg-query -W -f='\${source:Package} \${source:Version}\\n' 패키지명</code></pre>
      <div class="version-fields">
        <label>Debian 릴리스·소스 패키지<select name="debianPackage" required>
          <option value="">선택해 주세요</option>
          ${rows.map((row,index) => `<option value="${index}">${escape(debianSuites[row.suite] || row.suite)} · ${escape(row.package)}</option>`).join('')}
        </select></label>
        <label>Debian 설치 소스 버전<input name="debianVersion" required maxlength="150" spellcheck="false" autocomplete="off" placeholder="예: 1:3.2.1-1+deb12u1"></label>
      </div>
      <button type="submit" class="outline">Debian 버전 대조</button>
      <div class="version-result" role="status" hidden></div>
    </form>` : '<p class="version-hint">Debian 공식 데이터에서 릴리스별 수정 버전을 확인하지 못했습니다.</p>'}
    <div class="version-sources">${link(debianRecordUrl(item), 'Debian Security Tracker 원문')}</div>
  </details>`;
}

function showDebianVersionResult(form, item) {
  const result = form.querySelector('.version-result');
  const key = form.elements.debianPackage.value;
  const entry = key ? item?.debianPackages?.[Number(key)] : null;
  if (!entry) return;
  const compared = compareDebianVersions(form.elements.debianVersion.value.trim(), entry.fixed);
  const status = data.sources?.['Debian Security Tracker'];
  const fresh = status?.state === 'ok';
  const text = !fresh ? '이전 수집 자료 · Debian 원문에서 최신 수정 상태를 확인하세요.'
    : compared === null ? '추가 확인 필요 · Debian 소스 패키지 버전 형식을 확인하세요.'
    : compared >= 0 ? 'Debian 수정 패키지 버전 기준 충족' : 'Debian 수정 패키지보다 이전 버전';
  result.dataset.summary = [
    `Debian ${entry.suite} · ${entry.package}`,
    `입력 버전: ${form.elements.debianVersion.value.trim()}`, text,
    `공식 수정 버전 · ${entry.fixed}`,
    status?.at && `자료 확인 · ${date(status.at)}`,
  ].filter(Boolean).join('\n');
  result.innerHTML = `<strong>${text}</strong><p>공식 수정 버전 · ${escape(entry.fixed)}</p>
    ${status?.at ? `<p>자료 확인 · ${escape(date(status.at))}</p>` : ''}
    <p>${link(debianRecordUrl(item), '해당 CVE의 Debian 원문')}</p>`;
  result.hidden = false;
}

const debianDialog = $('#debian-dialog');
let debianLookupPromise;
let debianLookupItem;

$('#open-debian-lookup').addEventListener('click', () => debianDialog.showModal());
$('#debian-lookup').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = event.target.elements.cve;
  const id = input.value.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return;
  const status = debianDialog.querySelector('[data-debian-lookup-status]');
  const output = debianDialog.querySelector('[data-debian-lookup-result]');
  status.textContent = 'Debian 공식 수정 패키지 목록을 확인하고 있습니다.';
  output.replaceChildren();
  try {
    debianLookupPromise ||= fetch('./debian-packages.json', {cache:'no-cache'}).then((response) => {
      if (!response.ok) throw Error(`Debian index HTTP ${response.status}`);
      return response.json();
    }).catch((error) => {
      debianLookupPromise = undefined;
      throw error;
    });
    const lookup = await debianLookupPromise;
    if (input.value.trim().toUpperCase() !== id) return;
    debianLookupItem = {id, debianPackages:lookup[id] || []};
    output.innerHTML = debianPackageCheck(debianLookupItem);
    output.querySelector('details').open = true;
    status.textContent = `${id} · 수정 패키지 기록 ${debianLookupItem.debianPackages.length}건`;
  } catch {
    if (input.value.trim().toUpperCase() !== id) return;
    status.textContent = 'Debian 목록을 불러올 수 없습니다. 잠시 뒤 다시 조회하세요.';
    output.innerHTML = link(debianRecordUrl({id}), 'Debian Security Tracker 원문');
  }
});
debianDialog.addEventListener('submit', (event) => {
  if (!event.target.matches('[data-debian-check]')) return;
  event.preventDefault();
  showDebianVersionResult(event.target, debianLookupItem);
});

function installedVersionCheck(item) {
  const products = comparisonProducts(item);
  const cnaLink = link(`https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`, 'CNA 원문');
  const vendorLinks = (item.cna?.references || []).map((url) => link(url, '벤더 공지')).filter(Boolean);
  return `
    <details class="version-check">
      <summary>설치 버전·영향 조건 대조</summary>
      ${products.length ? `
      <form data-version-check>
        <p class="version-hint">입력값은 현재 브라우저 탭에서만 유지됩니다. 제품과 설치 버전은 공지에 쓰인 형식으로 입력하세요.
          ${products.some((product) => product.officialTakes || checkpointHotfixRanges(product).length) ? ' Check Point Jumbo Hotfix 대상은 릴리스와 Take를 함께 입력하세요. 예: R82.10 Take 50' : ''}</p>
        <label class="batch-toggle"><input type="checkbox" name="batch"> 여러 버전 일괄 대조</label>
        <div class="version-fields">
          <label>공지 제품<select name="product" required>
            ${products.length > 1 ? '<option value="">제품·플랫폼 선택</option>' : ''}
            ${products.map((product, index) => `<option value="${index}">${escape(compareProductLabel(product, item.product))}</option>`).join('')}
          </select></label>
          <label>설치 버전<input name="version" required maxlength="100" placeholder="예: 3.4.1" spellcheck="false" autocomplete="off"></label>
          <label hidden>설치 버전 목록<textarea name="versions" rows="4" maxlength="11000" placeholder="한 줄에 한 버전 또는 빌드, 최대 100줄" spellcheck="false" disabled></textarea></label>
          <label>설치 유형<select name="build">
            <option value="">선택해 주세요</option>
            <option value="upstream">공지 대상 제품의 릴리스</option>
            <option value="downstream">배포판 패키지·백포트·자체 빌드</option>
          </select></label>
          <label>벤더 공지의 영향 조건<select name="conditions">
            <option value="">확인 전</option>
            <option value="met">공지의 영향 조건에 해당</option>
            <option value="not-met">공지에 명시된 필수 조건에 해당하지 않음</option>
          </select></label>
        </div>
        <button type="submit" class="outline">대조 결과 보기</button>
        <div role="status" class="version-result" hidden></div>
      </form>` : '<p>구조화된 제품·버전 정보가 없어 자동 대조할 수 없습니다. 원문에서 영향 범위와 패치 버전을 확인하세요.</p>'}
      <div class="version-sources">${cnaLink} ${vendorLinks.join(' ')}</div>
    </details>`;
}

const hotfixBoundary = /^(R\d+(?:\.\d+)?) with Jumbo Hotfix Take (\d+) or below$/i;
const hotfixInput = /^(R\d+(?:\.\d+)?)(?:\s+(?:with\s+)?(?:Jumbo Hotfix\s+)?Take\s+(\d+))?$/i;

function checkpointHotfixRanges(product) {
  if (!/^check\s*point$/i.test(product.vendor) ||
    !/^Quantum Security (Gateway|Management)$/i.test(product.product)) return [];
  return (product.versions || []).flatMap((entry) => {
    const match = hotfixBoundary.exec(entry.version);
    return match && entry.status === 'affected' && !entry.lessThan && !entry.lessThanOrEqual && !entry.changes?.length
      ? [{entry, release:match[1].toUpperCase(), max:BigInt(match[2])}] : [];
  });
}

const kisaAffectedTake = /^(R\d+(?:\.\d+)?) Jumbo Hotfix Take (\d+) 이하$/i;
const kisaFixedTake = /^(R\d+(?:\.\d+)?) Jumbo Hotfix Take (\d+) 이상$/i;

function comparisonProducts(item) {
  const products = new Map();
  for (const patch of item.officialPatches || []) {
    const affected = kisaAffectedTake.exec(patch.affected);
    const fixed = kisaFixedTake.exec(patch.fixed);
    if (!affected || !fixed || affected[1].toUpperCase() !== fixed[1].toUpperCase()
      || BigInt(affected[2]) >= BigInt(fixed[2])) continue;
    if (!products.has(patch.product)) products.set(patch.product, []);
    products.get(patch.product).push({
      patch, release:affected[1].toUpperCase(), affectedMax:BigInt(affected[2]), fixedMin:BigInt(fixed[2]),
    });
  }
  return [...(item.cna?.affected || []), ...[...products].map(([product, officialTakes]) =>
    ({product, vendor:'KISA 공지', officialTakes}))];
}

function evaluateOfficialHotfix(product, version) {
  const parsed = hotfixInput.exec(version);
  const release = parsed?.[1].toUpperCase();
  if (!parsed?.[2]) return {status:'unknown', reason:'설치 릴리스와 Jumbo Hotfix Take를 함께 입력하세요. 예: R82.10 Take 50'};
  const matches = product.officialTakes.filter((entry) => entry.release === release);
  if (!matches.length) return {status:'unknown', reason:'선택한 제품의 해당 릴리스는 공식 표에서 확인해 주세요.'};
  if (matches.some(({patch}) => patch.fresh !== true)) return {status:'unknown', reason:'이전 수집 자료입니다. KISA 원문에서 최신 해결 기준을 확인하세요.'};
  const take = BigInt(parsed[2]);
  const candidates = matches.map((entry) => {
    const {patch, affectedMax, fixedMin} = entry;
    if (take <= affectedMax) return {status:'affected', reason:patch.affected};
    if (take >= fixedMin) return {status:'fixed', reason:patch.fixed};
    return {status:'unknown', reason:`영향 기준 ${patch.affected} / 해결 기준 ${patch.fixed} 사이입니다. 원문 확인이 필요합니다.`};
  });
  if (new Set(matches.map(({affectedMax, fixedMin}) => `${affectedMax}/${fixedMin}`)).size > 1) {
    return {status:'unknown', reason:'같은 제품과 릴리스에 서로 다른 공식 기준이 있습니다. 원문을 직접 확인하세요.'};
  }
  return candidates[0];
}

function evaluateCheckpointHotfix(product, version) {
  const ranges = checkpointHotfixRanges(product);
  if (!ranges.length) return null;
  const parsed = hotfixInput.exec(version);
  if (!parsed) return {status:'unknown', reason:'설치 릴리스와 Jumbo Hotfix Take를 함께 입력하세요. 예: R82.10 Take 50'};
  const [, release, take] = parsed;
  const matching = ranges.filter((range) => range.release === release.toUpperCase());
  if (!matching.length) return null;
  if (!take) return {status:'unknown', reason:`${release.toUpperCase()}의 Jumbo Hotfix Take 번호가 필요합니다. 관리 콘솔에서 확인하세요.`};

  const within = matching.filter(({max}) => BigInt(take) <= max);
  const parsedEntries = new Set(ranges.map(({entry}) => entry));
  const other = (product.versions || []).filter((entry) => !parsedEntries.has(entry));
  const otherResults = other.map((entry) => evaluateVersionEntry(entry, version, null));
  if (within.length && otherResults.every((status) => ['outside', 'affected'].includes(status))) {
    return {status:'affected', reason:versionLabel(within[0].entry)};
  }
  return {status:'unknown', reason:within.length
    ? '동일 제품에 추가 버전 조건이 있습니다. 벤더 공지에서 조건을 함께 대조하세요.'
    : `${release.toUpperCase()}의 명시된 영향 Take 범위를 벗어났습니다. 수정 적용 여부는 벤더 공지에서 확인하세요.`};
}

function installedVersionOutcome(product, version, build, conditions) {
  const upstream = build === 'upstream';
  const result = !upstream ? null : product.officialTakes ? evaluateOfficialHotfix(product, version)
    : evaluateCheckpointHotfix(product, version) || evaluateInstalledVersion(product, version);
  let status = 'unknown';
  let headline = '추가 확인 필요';
  let explanation = '벤더 공지에서 제품 에디션·기능 설정과 영향 조건을 확인하세요.';
  if (!upstream) {
    explanation = '배포판·백포트·자체 빌드는 설치 패키지 릴리스와 해당 공급사의 보안 공지로 확인하세요.';
    if (!build) explanation = '설치 유형을 선택하면 공지 범위와 대조할 수 있습니다.';
  } else if (result.status === 'fixed') {
    status = 'fixed';
    headline = '공식 공지 해결 버전 기준 충족';
    explanation = '선택한 제품·릴리스의 해결 Take 기준을 충족합니다.';
  } else if (result.status === 'unaffected') {
    status = 'unaffected';
    headline = '공지상 해당 버전은 영향 없음';
    explanation = '선택한 제품·플랫폼의 공지 범위를 기준으로 확인했습니다.';
  } else if (result.status === 'affected' && conditions === 'met') {
    status = 'affected';
    headline = '공지상 영향 조건에 해당';
    explanation = '확인한 조건과 설치 버전을 기준으로 패치 또는 완화조치를 검토하세요.';
  } else if (result.status === 'affected' && !conditions) {
    headline = '설치 버전은 영향 범위에 해당';
    explanation = '악용 전제조건을 확인하세요.';
  } else if (result.status === 'affected' && conditions === 'not-met') {
    headline = '설치 버전은 영향 범위에 해당';
    explanation = '확인한 필수 조건과 다른 악용 경로가 있는지 공지에서 다시 대조하세요.';
  }
  const versionStatus = {fixed:'공식 해결 기준 충족', affected:'영향 범위 해당', unaffected:'공지상 영향 없음'}[result?.status] || '추가 확인 필요';
  const conditionStatus = {met:'해당으로 입력', 'not-met':'해당하지 않음으로 입력'}[conditions] || '확인 전';
  return {status, headline, explanation, result, versionStatus, conditionStatus};
}

const batchLabels = {fixed:'공식 해결 기준 충족', affected:'영향 범위 해당', unaffected:'공지상 영향 없음', unknown:'추가 확인 필요'};
const cnaRecordUrl = (item) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`;
const nvdRecordUrl = (item) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`;
const advisoryReferences = (item) => [...new Set([...(item.cna?.references || []), ...(item.references || [])]
  .map(publicUrl).filter(Boolean))];
const patchVersionPattern = /\b\d+(?:\.\d+)+(?:[A-Za-z0-9+~_-]+(?:\.[A-Za-z0-9+~_-]+)*)?/g;

function patchRecords(item) {
  if (Array.isArray(item.patchEvidence)) return item.patchEvidence;
  return [
    ...(item.fixes || []).map((version) => ({version, source:'cve.now 수정 정보', url:item.url, text:version})),
    ...(item.describedFixes || []).map((version) => ({version, source:'수집 설명 추출',
      url:item.descriptionEnSource === 'NVD' ? nvdRecordUrl(item) : cnaRecordUrl(item), text:item.descriptionEn})),
  ].filter(({version}) => version.match(patchVersionPattern)?.[0] === version);
}

function patchProduct(item, patch) {
  return Number.isInteger(patch.productIndex) ? item.cna?.affected?.[patch.productIndex] : undefined;
}

function patchEvidenceDetails(patches) {
  return patches.map(({version, source, url, text}) => `<details>
    <summary>${escape(version)} · ${escape(source)}</summary>
    <p>${escape(text)}</p>${link(url, '근거 원문')}</details>`).join('');
}

function officialPatchEvidence(item) {
  const rows = item.officialPatches || [];
  if (!rows.length) return '';
  return `<details open><summary>KISA 제품별 공식 패치 기준 · ${rows.length}건</summary><ul class="detail-list">
    ${rows.map(({product,affected,fixed,url,fresh}) => `<li><strong>${escape(product)}</strong> · 영향 ${escape(affected)} → 해결 ${escape(fixed)}${fresh ? '' : ' · 이전 수집'} · ${link(url, '원문')}</li>`).join('')}
  </ul></details>`;
}

function groupedPatchEvidence(item) {
  const patches = patchRecords(item);
  const official = officialPatchEvidence(item);
  if (!patches.length && official) return official;
  if (!patches.length) return `<p>수집된 수정 버전 미확인 · ${link(cnaRecordUrl(item), 'CNA 원문')}</p>`;
  const groups = new Map();
  for (const patch of patches) {
    const product = patchProduct(item, patch);
    const label = product ? compareProductLabel(product, item.product) : '제품·릴리스 적용 범위 확인 필요';
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(patch);
  }
  return official + [...groups].map(([label, records]) => `<div class="affected-product">
    <strong>${escape(label)}</strong>${patchEvidenceDetails(records)}</div>`).join('');
}

function csvCell(value) {
  const text = String(value ?? '');
  const safe = /^[\s\uFEFF]*[=+@-]|^[\t\r\n]/.test(text) ? "'" + text : text;
  return '"' + safe.replace(/"/g, '""') + '"';
}

function downloadBatchCsv(button, item) {
  const form = button.closest('[data-version-check]');
  const product = item && form.elements.product.value !== '' ? comparisonProducts(item)[Number(form.elements.product.value)] : undefined;
  const rows = [...form.querySelectorAll('[data-version-status]:not([hidden])')];
  if (!product || !rows.length) return;
  const vendors = advisoryReferences(item);
  const header = ['CVE', '제품', '설치 버전', '버전 판정', '악용 조건', '판정 근거', 'CNA 출처', '벤더 공지·패치 참고'];
  const body = rows.map((row) => [
    item.id, compareProductLabel(product, item.product), ...[...row.cells].map((cell) => cell.textContent.trim()),
    cnaRecordUrl(item), vendors.join(' '),
  ]);
  const csv = '\uFEFF' + [header, ...body].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  downloadBlob(new Blob([csv], {type:'text/csv;charset=utf-8'}), `${item.id}-version-check.csv`);
}

function parseAssetCsv(text, delimiter, limit = 5001) {
  const records = [];
  let record = [];
  let field = '';
  let quoted = false;
  let closed = false;
  const addField = () => {
    record.push(field);
    field = '';
    closed = false;
  };
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        quoted = false;
        closed = true;
      } else field += char;
    } else if (char === delimiter) addField();
    else if (char === '\r' || char === '\n') {
      addField();
      records.push(record);
      if (records.length === limit) {
        if (limit === 1 || !text.slice(i + 1).trim()) return records;
        throw Error('자산은 한 파일에 최대 5,000행까지 대조할 수 있습니다.');
      }
      record = [];
      if (char === '\r' && text[i + 1] === '\n') i++;
    } else if (char === '"' && !field && !closed) quoted = true;
    else if (closed || char === '"') throw Error('CSV의 따옴표 형식을 확인하세요.');
    else field += char;
  }
  if (quoted) throw Error('CSV에 닫히지 않은 따옴표가 있습니다.');
  if (field || closed || record.length) {
    addField();
    records.push(record);
  }
  return records;
}

function readAssetCsv(bytes) {
  const signature = new Uint8Array(bytes, 0, Math.min(2, bytes.byteLength));
  const encoding = signature[0] === 255 && signature[1] === 254 ? 'utf-16le'
    : signature[0] === 254 && signature[1] === 255 ? 'utf-16be' : 'utf-8';
  let text;
  try {
    text = new TextDecoder(encoding, {fatal:true}).decode(bytes);
  } catch {
    try {
      if (encoding !== 'utf-8') throw Error();
      text = new TextDecoder('euc-kr', {fatal:true}).decode(bytes);
    } catch {
      throw Error('파일을 읽을 수 없습니다. UTF-8 또는 CP949 CSV로 저장해 주세요.');
    }
  }
  if (text.includes('\0')) throw Error('CSV 파일의 형식과 인코딩을 확인하세요.');
  const candidates = [',', ';', '\t'].flatMap((delimiter) => {
    try {
      return [{delimiter, width:parseAssetCsv(text, delimiter, 1)[0]?.length || 0}];
    } catch {
      return [];
    }
  }).sort((a, b) => b.width - a.width);
  if (!candidates.length) throw Error('CSV의 첫 행과 따옴표 형식을 확인하세요.');
  const [headers, ...rows] = parseAssetCsv(text, candidates[0].delimiter);
  if (!headers?.some((value) => value.trim()) || headers.length > 150) {
    throw Error('첫 행에 CSV 열 이름이 있어야 합니다. 최대 150열까지 지원합니다.');
  }
  const records = rows.map((cells, index) => ({cells, number:index + 2}))
    .filter(({cells}) => cells.some((value) => value.trim()));
  if (!records.length) throw Error('헤더 아래에 대조할 자산 행이 없습니다.');
  if (records.some(({cells}) => cells.length > headers.length)) {
    throw Error('헤더보다 열이 많은 행이 있습니다. CSV의 구분자와 따옴표를 확인하세요.');
  }
  return {headers, records};
}

const assetName = (value) => String(value || '').normalize('NFKC').toLowerCase().trim().replace(/\s+/g, ' ');
const assetHeaderAliases = {
  assetId: ['asset id','asset_id','asset','hostname','host','자산 id','자산명','호스트명','자산코드'],
  version: ['installed version','installed_version','version','설치 버전','설치버전','버전'],
  product: ['product','software','제품','제품명','소프트웨어'],
  exposure: ['external exposure','internet exposed','exposure','외부 노출','외부노출','외부 노출 여부'],
  build: ['build type','installation type','설치 유형','빌드 유형'],
  conditions: ['exploit conditions','conditions','영향 조건','영향조건','악용 조건'],
};
const assetExposure = {
  yes: ['예','y','yes','true','1','외부 노출','외부','public','external'],
  no: ['아니오','아니요','n','no','false','0','내부 전용','내부','internal','private'],
};
const assetBuild = {
  upstream: ['upstream','공지 대상 제품 릴리스','공지 대상 제품의 릴리스'],
  downstream: ['downstream','배포판 패키지','배포판 패키지·백포트·자체 빌드','백포트','자체 빌드'],
};
const assetConditions = {
  met: ['met','해당','조건 충족'],
  'not-met': ['not-met','미해당','해당 없음','조건 미충족'],
};
const assetValue = (mapping, value) => Object.keys(mapping).find((key) => mapping[key].includes(assetName(value))) || '';
const assetExposureLabels = {yes:'외부 노출', no:'내부 전용', '':'미확인'};
const multiAssetLabels = {...batchLabels, not_comparable:'대조 불가'};
const assetExposureOrder = {yes:0, no:1, '':2};

function compareAssetRows(records, products, item, mapping, multiple = false) {
  const names = products.map((product) => new Set([
    [compareProductLabel(product, item.product), ...(product.programFiles || [])].join(' · '),
    ...(!product.platforms?.length && !product.modules?.length && !product.programFiles?.length ? [
      product.product, [product.vendor, product.product].filter(Boolean).join(' '),
    ] : []),
  ].filter(Boolean).map(assetName)));
  return records.map(({cells, number}) => {
    const value = (field) => (cells[mapping[field]] || '').trim();
    const productName = value('product');
    const normalizedProduct = assetName(productName);
    const matches = normalizedProduct ? names.flatMap((labels, index) =>
      labels.has(normalizedProduct) ? [index] : []) : [];
    const product = mapping.product === '' ? products[mapping.singleProduct]
      : matches.length === 1 ? products[matches[0]] : undefined;
    const version = value('version');
    const exposure = assetValue(assetExposure, value('exposure'));
    const build = mapping.build === '' ? mapping.defaultBuild : assetValue(assetBuild, value('build'));
    const conditions = assetValue(assetConditions, value('conditions'));
    const row = {cve:item.id, number, id:value('assetId') || `CSV ${number}행`,
      product:product ? compareProductLabel(product, item.product) : productName || '미확인',
      version, exposure, source:cnaRecordUrl(item)};
    if (!product || !version || version.length > 100) {
      return {...row, status:multiple && !product ? 'not_comparable' : 'unknown',
        versionStatus:'추가 확인 필요', conditionStatus:'판정 전',
        reason: !product ? (matches.length > 1 ? '일치하는 공지 제품 범위가 여러 개입니다.'
          : products.length ? 'CSV 제품명이 공지의 제품·플랫폼과 일치하는지 확인하세요.'
            : '공지에 자동 대조할 제품·버전 기준이 없습니다.')
          : !version ? '설치 버전이 비어 있습니다.' : '설치 버전이 100자를 초과합니다.'};
    }
    const outcome = installedVersionOutcome(product, version, build, conditions);
    const officialUrl = product.officialTakes?.find(({release}) => release === hotfixInput.exec(version)?.[1].toUpperCase())?.patch.url;
    const status = multiple && outcome.result?.status === 'unknown' ? 'not_comparable' : outcome.status;
    return {...row, status, versionStatus:outcome.versionStatus, conditionStatus:outcome.conditionStatus,
      conditionPending:outcome.result?.status === 'affected' && !conditions,
      source:publicUrl(officialUrl) || row.source,
      reason:[outcome.result?.reason, outcome.status === 'unknown' && outcome.explanation].filter(Boolean).join(' · ')};
  });
}

const assetDialog = $('#asset-dialog');
const assetForm = $('#asset-form');
const assetFile = $('#asset-file');
const assetStatus = $('#asset-status');
const assetResultFilter = $('#asset-result-filter');
const assetCveFilter = $('#asset-cve-filter');
const assetPicker = $('#asset-picker');
const assetQuery = $('#asset-cve-query');
const assetCandidates = $('#asset-candidates');
const assetSelectionLimit = 5;
const assetExternalOnly = $('#asset-external-only');
const assetPageSize = 50;
let assetSession;
let displayedAssets = [];
let assetPage = 0;

function resetAssetResult() {
  displayedAssets = [];
  assetPage = 0;
  if (assetSession) assetSession.results = [];
  $('#asset-results').hidden = true;
  $('#asset-table').replaceChildren();
  $('#asset-totals').textContent = '';
  $('#asset-page').textContent = '';
}

function openAssetCsv(item) {
  const multiple = !item;
  assetSession = {multiple, results:[], targets:item ? [{item, products:comparisonProducts(item)}] : [],
    candidates:multiple ? [...new Map([...priorities, ...data.cves].map((entry) => [entry.id, entry])).values()] : [],
    chosen:new Set()};
  resetAssetForm();
  assetPicker.hidden = !multiple;
  assetForm.hidden = multiple;
  $('#asset-cve').textContent = item?.id || '';
  for (const control of assetDialog.querySelectorAll('[data-single-asset]')) control.hidden = multiple;
  $('#asset-multi-note').hidden = !multiple;
  if (multiple) {
    assetQuery.value = '';
    renderAssetCandidates();
  }
  assetDialog.showModal();
  if (multiple) assetQuery.focus();
}

function updateAssetSelection() {
  const {chosen} = assetSession;
  $('#asset-cve-selection').textContent = chosen.size
    ? `${chosen.size}/${assetSelectionLimit}건 선택 · ${[...chosen].join(', ')}`
    : `0/${assetSelectionLimit}건 선택`;
  $('#asset-cve-continue').disabled = !chosen.size;
  for (const control of assetCandidates.querySelectorAll('input')) {
    control.disabled = chosen.size >= assetSelectionLimit && !control.checked;
  }
}

function renderAssetCandidates() {
  const query = assetQuery.value.trim();
  const entries = assetSession.candidates.filter((entry) => !query || cveSearchMatch(entry, query) !== null);
  const visible = query ? entries : [...entries.filter((entry) => assetSession.chosen.has(entry.id)),
    ...entries.filter((entry) => !assetSession.chosen.has(entry.id))];
  assetCandidates.innerHTML = visible.slice(0, 20).map((entry) => `<label>
    <input type="checkbox" value="${escape(entry.id)}" ${assetSession.chosen.has(entry.id) ? 'checked' : ''}>
    <span><strong>${escape(entry.id)}</strong> ${escape(entry.titleKo || entry.title)}</span>
  </label>`).join('') + (visible.length > 20 ? '<p class="feed-note">상위 20건 표시 · 검색으로 범위를 좁힐 수 있습니다.</p>' : '')
    || '<p class="feed-note">현재 수집 목록에 검색 결과가 없습니다.</p>';
  updateAssetSelection();
}

$('#open-multi-asset').addEventListener('click', () => openAssetCsv());
assetQuery.addEventListener('input', renderAssetCandidates);
assetCandidates.addEventListener('change', (event) => {
  if (!event.target.matches('input[type="checkbox"]')) return;
  const {value, checked} = event.target;
  if (checked && assetSession.chosen.size < assetSelectionLimit) assetSession.chosen.add(value);
  else if (!checked) assetSession.chosen.delete(value);
  updateAssetSelection();
});
$('#asset-cve-continue').addEventListener('click', () => {
  assetSession.targets = assetSession.candidates.filter((item) => assetSession.chosen.has(item.id))
    .map((item) => ({item, products:comparisonProducts(item)}));
  if (!assetSession.targets.length) return;
  $('#asset-cve').textContent = assetSession.targets.map(({item}) => item.id).join(' · ');
  assetPicker.hidden = true;
  assetForm.hidden = false;
  assetFile.focus();
});

function resetAssetForm() {
  assetForm.reset();
  assetStatus.textContent = '';
  $('#asset-fields').hidden = true;
  resetAssetResult();
}

assetDialog.addEventListener('close', () => {
  assetSession = undefined;
  resetAssetForm();
  $('#asset-cve').textContent = '';
  assetCandidates.replaceChildren();
  assetQuery.value = '';
  $('#asset-condition-columns').replaceChildren();
  assetCveFilter.replaceChildren();
  for (const key of [...Object.keys(assetHeaderAliases), 'singleProduct']) {
    assetForm.elements[key].replaceChildren();
  }
});

assetFile.addEventListener('change', async () => {
  const session = assetSession;
  const file = assetFile.files[0];
  if (!session) return;
  session.records = undefined;
  resetAssetResult();
  $('#asset-fields').hidden = true;
  $('#asset-multi-conditions').hidden = true;
  $('#asset-condition-columns').replaceChildren();
  assetStatus.textContent = '';
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    assetStatus.textContent = '2MB 이하의 CSV 파일을 선택하세요.';
    return;
  }
  assetStatus.textContent = '브라우저에서 CSV를 읽고 있습니다.';
  try {
    const bytes = await file.arrayBuffer();
    if (session !== assetSession || assetFile.files[0] !== file) return;
    const {headers, records} = readAssetCsv(bytes);
    session.records = records;
    const columnOptions = (placeholder) => [new Option(placeholder, ''), ...headers
      .map((label, index) => new Option(`${index + 1}. ${label.trim() || '이름 없는 열'}`, index))];
    for (const [key, aliases] of Object.entries(assetHeaderAliases)) {
      const control = assetForm.elements[key];
      control.replaceChildren(...columnOptions(key === 'version' ? '열을 선택하세요' : '연결 안 함'));
      const matches = headers.flatMap((label, index) => aliases.includes(assetName(label)) ? [index] : []);
      control.value = matches.length === 1 ? matches[0] : '';
    }
    if (session.multiple) {
      const fields = $('#asset-condition-columns');
      for (const {item} of session.targets) {
        const label = document.createElement('label');
        label.textContent = `${item.id} 영향 조건 열`;
        const select = document.createElement('select');
        select.dataset.assetConditions = item.id;
        select.replaceChildren(...columnOptions('연결 안 함'));
        label.append(select);
        fields.append(label);
      }
      $('#asset-multi-conditions').hidden = false;
    } else {
      const [{item, products}] = session.targets;
      assetForm.elements.singleProduct.replaceChildren(new Option('공지 제품을 선택하세요', ''),
        ...products.map((product, index) => new Option(compareProductLabel(product, item.product), index)));
    }
    assetForm.elements.defaultBuild.value = '';
    syncAssetMapping();
    $('#asset-fields').hidden = false;
    assetStatus.textContent = `자산 ${records.length.toLocaleString('ko-KR')}행을 읽었습니다. CSV 열 연결을 확인하세요.`;
  } catch (error) {
    if (session === assetSession && assetFile.files[0] === file) assetStatus.textContent = error.message;
  }
});

function syncAssetMapping() {
  const {product, singleProduct, build, defaultBuild, conditions} = assetForm.elements;
  const multiple = assetSession?.multiple === true;
  product.required = multiple;
  singleProduct.required = !multiple && product.value === '';
  singleProduct.disabled = multiple || product.value !== '';
  conditions.disabled = multiple;
  defaultBuild.disabled = build.value !== '';
}

assetForm.addEventListener('change', (event) => {
  if (event.target === assetFile) return;
  syncAssetMapping();
  if (assetSession?.results.length) {
    resetAssetResult();
    assetStatus.textContent = '열 연결이 바뀌었습니다. 다시 대조해 주세요.';
  }
});

assetForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const session = assetSession;
  if (!session?.records?.length) return;
  const mapping = Object.fromEntries([...Object.keys(assetHeaderAliases), 'singleProduct', 'defaultBuild']
    .map((key) => [key, assetForm.elements[key].value]));
  const conditionColumns = new Map([...assetForm.querySelectorAll('[data-asset-conditions]')]
    .map((field) => [field.dataset.assetConditions, field.value]));
  if (session.multiple) mapping.conditions = '';
  const assigned = [...Object.keys(assetHeaderAliases).map((key) => mapping[key]), ...conditionColumns.values()].filter(Boolean);
  if (new Set(assigned).size !== assigned.length) {
    assetStatus.textContent = 'CSV 열 하나를 두 항목에 연결했습니다. 열 연결을 확인하세요.';
    return;
  }
  session.results = session.targets.flatMap(({item, products}) => compareAssetRows(session.records, products, item,
    session.multiple ? {...mapping, conditions:conditionColumns.get(item.id) || ''} : mapping, session.multiple))
    .sort((a, b) => assetExposureOrder[a.exposure] - assetExposureOrder[b.exposure] || a.number - b.number);
  const labels = session.multiple ? multiAssetLabels : batchLabels;
  assetResultFilter.replaceChildren(new Option('전체', ''),
    ...Object.entries(labels).map(([key, label]) => new Option(label, key)));
  if (session.multiple) assetResultFilter.add(new Option('영향 버전 · 조건 미확인', 'condition_pending'));
  assetCveFilter.replaceChildren(new Option('모든 CVE', ''),
    ...session.targets.map(({item}) => new Option(item.id, item.id)));
  $('#asset-cve-filter-label').hidden = !session.multiple;
  assetExternalOnly.checked = false;
  const counts = Object.fromEntries(Object.keys(labels).map((key) => [key, 0]));
  session.results.forEach(({status}) => counts[status]++);
  $('#asset-totals').textContent = [
    session.multiple ? `자산 ${session.records.length}행 × CVE ${session.targets.length}건 = ${session.results.length}건`
      : `총 ${session.results.length}행`,
    ...Object.entries(labels).map(([key,label]) => `${label} ${counts[key]}${session.multiple ? '건' : '행'}`),
  ].join(' · ');
  assetStatus.textContent = '자산 대조를 완료했습니다.';
  $('#asset-results').hidden = false;
  filterAssetResults();
});

function renderAssetResults() {
  const start = assetPage * assetPageSize;
  const rows = displayedAssets.slice(start, start + assetPageSize);
  const multiple = assetSession.multiple;
  $('#asset-table').innerHTML = rows.length ? `<div class="batch-results"><table class="${multiple ? 'asset-multi-table' : ''}">
    <thead><tr><th scope="col">자산 ID</th>${multiple ? '<th scope="col">CVE</th>' : ''}<th scope="col">제품 · 설치 버전</th><th scope="col">외부 노출</th>
      <th scope="col">판정</th><th scope="col">근거</th></tr></thead><tbody>
    ${rows.map((row) => `<tr><th scope="row">${escape(row.id)}</th>
      ${multiple ? `<td>${escape(row.cve)}</td>` : ''}<td>${escape(row.product)}<br>${escape(row.version || '버전 미확인')}</td>
      <td>${assetExposureLabels[row.exposure]}</td>
      <td><strong>${multiAssetLabels[row.status]}</strong><br><small>${row.versionStatus} · 조건 ${row.conditionStatus}</small></td>
      <td>${escape(row.reason)} ${link(row.source, '원문')}</td></tr>`).join('')}
    </tbody></table></div>` : '<p class="feed-note">선택한 필터에 해당하는 자산이 없습니다.</p>';
  $('#asset-page').textContent = rows.length ? `${start + 1}–${start + rows.length} / ${displayedAssets.length}행` : '0행';
  $('#asset-previous').disabled = assetPage === 0;
  $('#asset-next').disabled = start + assetPageSize >= displayedAssets.length;
  $('#asset-download').disabled = !displayedAssets.length;
}

function filterAssetResults() {
  const result = assetResultFilter.value;
  displayedAssets = assetSession.results.filter(({cve, status, exposure, conditionPending}) =>
    (!assetCveFilter.value || assetCveFilter.value === cve)
    && (!result || (result === 'condition_pending' ? conditionPending : result === status))
    && (!assetExternalOnly.checked || exposure === 'yes'));
  assetPage = 0;
  renderAssetResults();
}

assetResultFilter.addEventListener('change', filterAssetResults);
assetCveFilter.addEventListener('change', filterAssetResults);
assetExternalOnly.addEventListener('change', filterAssetResults);
$('#asset-previous').addEventListener('click', () => { assetPage--; renderAssetResults(); });
$('#asset-next').addEventListener('click', () => { assetPage++; renderAssetResults(); });
$('#asset-download').addEventListener('click', () => {
  const filename = assetSession.multiple ? 'security-insight-multi-cve' : assetSession.targets[0].item.id;
  const header = ['CVE', 'CSV 행', '자산 ID', '제품', '설치 버전', '외부 노출', '판정', '버전 판정', '영향 조건', '판정 근거', '출처'];
  const rows = displayedAssets.map((row) => [row.cve,row.number,row.id,row.product,row.version,assetExposureLabels[row.exposure],
    multiAssetLabels[row.status],row.versionStatus,row.conditionStatus,row.reason,row.source]);
  const csv = '\uFEFF' + [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  downloadBlob(new Blob([csv], {type:'text/csv;charset=utf-8'}), `${filename}-asset-check.csv`);
});

function showInstalledVersionResult(event, item) {
  event.preventDefault();
  const form = event.target.closest('[data-version-check]');
  if (form) renderInstalledVersionResult(form, item);
}

function renderInstalledVersionResult(form, item) {
  const fields = form.elements;
  const product = item && fields.product.value !== '' ? comparisonProducts(item)[Number(fields.product.value)] : undefined;
  if (!product || fields.product.value === '') return;
  const batch = fields.batch.checked;
  const versions = (batch ? fields.versions.value.split(/\r?\n/) : [fields.version.value])
    .map((version) => version.trim()).filter(Boolean);
  const output = form.querySelector('.version-result');
  output.hidden = false;
  delete output.dataset.summary;
  if (!versions.length || versions.length > 100 || versions.some((version) => version.length > 100)) {
    output.textContent = '설치 버전을 입력해 주세요. 최대 100줄까지, 한 줄에 100자 이내로 입력할 수 있습니다.';
    return;
  }
  const results = [...new Set(versions)].map((version) => ({
    version, ...installedVersionOutcome(product, version, fields.build.value, fields.conditions.value),
  }));
  const conditionNotes = [
    product.platforms?.length ? `플랫폼 · ${product.platforms.join(', ')}` : '',
    product.modules?.length ? `구성요소 · ${product.modules.join(', ')}` : '',
    ...attackConditions(item),
  ].filter(Boolean);
  const releases = new Set(versions.map((version) => hotfixInput.exec(version)?.[1].toUpperCase()).filter(Boolean));
  const officialEvidence = (entries) => entries.map(({patch}) => ({
    version:patch.fixed + (patch.fresh ? '' : ' · 이전 수집'),
    source:'KISA 보호나라', url:patch.url, text:`${patch.product} · 영향 ${patch.affected} / 해결 ${patch.fixed}`,
  }));
  const patches = product.officialTakes ? officialEvidence(product.officialTakes.filter(({release}) => releases.has(release)))
    : patchRecords(item).filter((patch) => patchProduct(item, patch) === product);
  const otherPatches = product.officialTakes && officialEvidence(product.officialTakes.filter(({release}) => !releases.has(release)));
  const otherReleaseEvidence = otherPatches?.length
    ? `<details><summary>다른 릴리스 기준 보기</summary>${patchEvidenceDetails(otherPatches)}</details>` : '';
  const fixNote = patches.length ? [...new Set(patches.map(({version}) => version))].join(', ')
    : '선택한 제품의 수정 버전 미확인 · 벤더 공지 참조';
  if (batch) {
    const counts = Object.entries(batchLabels).map(([status, label]) =>
      `${label} ${results.filter((entry) => entry.status === status).length}건`).join(' · ');
    output.dataset.summary = [counts, ...results.map(({version, versionStatus, conditionStatus}) => `${version} · 버전 ${versionStatus} · 악용 조건 ${conditionStatus}`),
      `수정 정보 · ${fixNote}`].join('\n');
    output.innerHTML = `<p>${escape(counts)}</p>
      <label>결과 필터 <select data-batch-filter>
        <option value="">전체</option><option value="review">영향 범위 해당 + 추가 확인 필요</option>
        ${Object.entries(batchLabels).map(([status, label]) => `<option value="${status}">${label}</option>`).join('')}
      </select></label>
      <button type="button" class="outline" data-export-batch>현재 결과 CSV 다운로드</button>
      <div class="batch-results"><table><thead><tr><th scope="col">설치 버전</th><th scope="col">버전 판정</th><th scope="col">악용 조건</th><th scope="col">판단 근거</th></tr></thead>
      <tbody>${results.map(({version, status, result, explanation, versionStatus, conditionStatus}) => `<tr data-version-status="${status}">
        <th scope="row">${escape(version)}</th><td>${versionStatus}</td><td>${conditionStatus}</td>
        <td>${escape(result?.reason || explanation)}</td></tr>`).join('')}</tbody></table></div>
      <p data-batch-empty hidden>이 조건에 해당하는 버전이 없습니다.</p>
      <p>수정 정보 · ${escape(fixNote)}</p>${patchEvidenceDetails(patches)}${otherReleaseEvidence}`;
    return;
  }
  const [{version, headline, explanation, result, versionStatus, conditionStatus}] = results;
  output.dataset.summary = [`입력 버전: ${version}`, headline, `설치 버전 판정 · ${versionStatus}`, `악용 조건 · ${conditionStatus}`, explanation, result && `버전 근거 · ${result.reason}`,
    conditionNotes.length && `제품·CVSS 참고 조건 · ${conditionNotes.join(' / ')}`, `수정 정보 · ${fixNote}`].filter(Boolean).join('\n');
  output.innerHTML = `
    <strong>${headline}</strong><p>설치 버전 판정 · ${versionStatus}<br>악용 조건 · ${conditionStatus}</p><p>${explanation}</p>
    ${result ? `<p>버전 근거 · ${escape(result.reason)}</p>` : ''}
    ${result?.status === 'unknown' && product.versions?.length ? `<details>
      <summary>CNA 버전 범위 직접 대조</summary>
      <ul class="detail-list">${product.versions.map((entry) => `<li>${escape(versionLabel(entry))}</li>`).join('')}</ul>
    </details>` : ''}
    ${conditionNotes.length ? `<p>제품·CVSS 참고 조건 · ${escape(conditionNotes.join(' / '))}</p>` : ''}
    <p>수정 정보 · ${escape(fixNote)}</p>${patchEvidenceDetails(patches)}${otherReleaseEvidence}`;
}

function bilingual(item) {
  const english = item.descriptionEn || item.description;
  const cached = publishedAdvisoryTranslations(item).find(([source]) => source === english)?.[1];
  const korean = item.descriptionKo || cached;
  const source = item.descriptionKo ? item.translationSource : cached ? '배포 전 기계 번역 · 원문 대조 필요' : '';
  const showMachine = english && !korean && 'Translator' in globalThis;
  return `
    <div class="bilingual">
      <div><h4>한국어${source ? ` <small>${escape(source)}</small>` : ''}</h4>
      <p class="cve-summary" data-translation>${escape(korean || '등록된 한국어 설명이 없습니다.')}</p>
      ${showMachine ? '<button class="utility" type="button" data-translate>한국어로 번역</button>' : ''}</div>
      <details class="english-original" lang="en"><summary>English original · 영문 원문</summary><p class="cve-summary">${escape(english || 'No English description was collected.')}</p></details>
    </div>`;
}

function technicalDetails(item) {
  const cna = item.cna || {};
  const conditions = attackConditions(item);
  const listOf = (entries) => `<ul class="detail-list">${entries.map((value) => `<li>${escape(value)}</li>`).join('')}</ul>`;
  return `
    <h3>취약점 설명</h3>
    ${bilingual(item)}
    <h3>영향 범위</h3>
    ${cna.affected?.length ? cna.affected.map((product) => `
      <div class="affected-product">
        <strong>${escape([product.vendor, product.product].filter(Boolean).join(' ') || item.product || '제품명 미확인')}</strong>
        ${product.platforms.length ? `<div>플랫폼 · ${escape(product.platforms.join(', '))}</div>` : ''}
        ${product.modules.length ? `<div>구성요소 · ${escape(product.modules.join(', '))}</div>` : ''}
        ${product.versions.length ? listOf(product.versions.map(versionLabel)) : '<p>개별 버전 범위 미기재</p>'}
        <small>목록 외 버전 · ${escape(versionStates[product.defaultStatus] || '미확인')}</small>
      </div>`).join('') : `<p>${escape(item.product || '제품명 미확인')} · 구조화된 영향 버전 미확인. 원문 공지를 확인해 주세요.</p>`}
    <h3>악용 조건</h3>
    ${conditions.length ? `${listOf(conditions)}<small>CVSS 벡터 기준입니다. 기능 활성화, 배포 형태 등 추가 조건은 위 설명과 공지에서 확인하세요.</small>`
      : '<p>구조화된 조건을 확인하지 못했습니다. 위 설명과 원문 공지에서 조건을 확인하세요.</p>'}
    <h3>패치 버전</h3>
    ${groupedPatchEvidence(item)}
    ${cna.solutions?.length ? `<small>CNA 해결책 원문</small>${listOf(cna.solutions)}` : ''}
    <h3>완화조치</h3>
    ${cna.workarounds?.length ? `<small>CNA 임시 조치 원문</small>${listOf(cna.workarounds)}`
      : '<p>수집한 CNA 레코드에서 임시 완화조치를 확인하지 못했습니다. 적용 전 벤더 공지의 우회책을 확인하세요.</p>'}
    ${item.requiredAction ? `<small>CISA KEV 권고 원문</small>${listOf([item.requiredAction])}` : ''}`;
}

async function translateDescription(button, item) {
  const answer = button.parentElement.querySelector('[data-translation]');
  button.disabled = true;
  answer.textContent = '브라우저에서 번역을 준비하고 있습니다.';
  let translator;
  try {
    translator = await Translator.create({sourceLanguage:'en', targetLanguage:'ko'});
    const source = item.descriptionEn || item.description;
    const translated = (await translator.translate(source)).trim();
    if (!validBrowserTranslation(source, translated)) {
      answer.textContent = '원문의 버전·경로·기술 용어를 확인해야 합니다. 아래 영문 원문을 참고하세요.';
      button.disabled = false;
      return;
    }
    answer.textContent = translated;
    button.textContent = '기계 번역 · 원문 대조 필요';
  } catch {
    answer.textContent = '이 브라우저에서 번역을 불러오지 못했습니다. 아래 영문을 확인하세요.';
    button.disabled = false;
  } finally {
    translator?.destroy();
  }
}

function affectedRanges(item) {
  return (item.cna?.affected || []).flatMap((product) => (product.versions || [])
    .filter((entry) => entry.status === 'affected' || (entry.changes || []).some((change) => change.status === 'affected'))
    .map((entry) => `${product.product || item.product || '제품 미확인'} · ${versionLabel(entry)}`));
}

function actionSummary(item) {
  const affected = item.cna?.affected || [];
  const ranges = affectedRanges(item);
  const conditions = attackConditions(item);
  const patches = patchRecords(item);
  const scopedPatches = [...new Set(patches.flatMap((patch) => {
    const product = patchProduct(item, patch);
    return product ? [`${product.product || item.product} · ${patch.version}`] : [];
  }))];
  const platforms = [...new Set(affected.flatMap((product) => product.platforms || []))];
  const modules = [...new Set(affected.flatMap((product) => product.modules || []))];
  const environment = briefingConditions[item.id]?.environment;
  const filters = [platforms.length ? `대상 플랫폼 · ${platforms.join(', ')}` : '',
    modules.length ? `구성요소 · ${modules.join(', ')}` : ''].filter(Boolean).join(' / ');
  const visibleRanges = ranges.slice(0, 3).map(escape).join('<br>');
  return `
    <section class="action-summary">
      <h3>조치 요약</h3>
      <dl>
        <div><dt>영향받는 환경</dt><dd>
          ${environment ? `<p class="summary-environment">${escape(environment)}</p>` : ''}
          ${visibleRanges || '명시된 영향 버전 미확인'}
          ${ranges.length > 3 ? `<br><small>외 ${ranges.length - 3}개 범위 · 아래 영향 범위에서 확인</small>` : ''}
        </dd></div>
        <div class="summary-first-check"><dt>첫 점검</dt><dd>
          <span>${escape(firstAssetCheck(item))}</span>
          ${conditions.length ? `<small>CVSS 조건 · ${escape(conditions.join(' / '))}</small>` : ''}
          ${filters ? `<small>${escape(filters)}</small>` : ''}
        </dd></div>
        <div><dt>조치·패치 근거</dt><dd>
          ${item.officialPatches?.length ? 'KISA 제품별 수정 기준 확인' : escape(scopedPatches.length ? scopedPatches.join(' / ') : patches.length ?
            '제품·릴리스별 적용 범위 확인 필요' : '수정 버전 미확인 · 벤더 공지 참조')}
          <p class="action-sources">
            ${link(item.cna?.references?.[0] || item.references?.[0], '벤더 공지')}
            ${item.notices?.[0] ? link(item.notices[0].url, 'KISA 보호나라 공지') : ''}
            ${(briefingConditions[item.id]?.sources || []).slice(0,1).map(([label,address]) => link(address,label)).join('')}
          </p>
        </dd></div>
      </dl>
    </section>`;
}

const historyTypes = {published:'신규 공개', kev:'KEV 등재', remediation:'패치·완화 정보 변경'};
const historyDate = (event) => event.type === 'kev' ? event.at : date(event.at);

function changeDetails(event) {
  if (!event.changes?.length) return '';
  return `<dl class="change-values">${event.changes.map((change) =>
    `<div><dt>${escape(change.field)}</dt><dd><strong>이전</strong> ${escape(change.before.join(' / ') || '수집 정보 없음')}</dd>
    <dd><strong>현재</strong> ${escape(change.after.join(' / ') || '수집 정보 없음')}</dd></div>`).join('')}</dl>`;
}

function remediationComparison(item, review) {
  const completed = completedRemediation(review);
  const current = remediationValues(item);
  const events = remediationSinceReview(item, review)
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  const rows = completed ? remediationFields.flatMap((field, index) => {
    const latest = events.find((event) => event.changes?.some((change) => change.field === field));
    const earliest = events.findLast((event) => event.changes?.some((change) => change.field === field));
    const earlier = completed[index] ?? earliest?.changes.find((change) => change.field === field)?.before
      ?? (field === '공식 제품별 패치 기준' ? [] : undefined);
    if (earlier === undefined || JSON.stringify(earlier) === JSON.stringify(current[index])) return [];
    const values = (value) => (Array.isArray(value) ? value : [value]).filter(Boolean);
    return [{field, before:values(earlier), after:values(current[index]), at:latest?.at}];
  }) : [];
  return {completed, events, rows};
}

function reviewComparison(item, state) {
  if (state !== 'done' && state !== 'recheck') return '';
  const review = preferences.reviews[item.id];
  const savedAt = Date.parse(review.completedAt);
  const baselineAt = Date.parse(review.reviewedThrough);
  const times = [
    Number.isFinite(savedAt) ? `완료 기록 ${date(savedAt)}` : '',
    Number.isFinite(baselineAt) ? `당시 데이터 ${date(baselineAt)}` : '',
  ].filter(Boolean);
  if (state === 'done') {
    return times.length ? `<p class="review-baseline" data-review-comparison>${escape(times.join(' · '))}</p>` : '';
  }
  const {completed, events, rows} = remediationComparison(item, review);
  const renderedValues = (values) => values.length ? values.map(escape).join('<br>') : '기록된 정보 없음';
  const sources = [
    link(`https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`, 'CNA 원문'),
    ...(item.cna?.references || []).map((url, index, urls) =>
      link(url, urls.length > 1 ? `벤더 공지 ${index + 1}` : '벤더 공지')),
    rows.some(({field}) => field === remediationFields[0]) && item.origin !== 'CISA KEV' ? link(item.url, 'cve.now') : '',
    rows.some(({field}) => field === remediationFields[3]) ? link(
      `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`, 'CISA KEV') : '',
    rows.some(({field}) => field === remediationFields[4]) ? link(nvdRecordUrl(item), 'NVD 범위 원문') : '',
    rows.some(({field}) => field === remediationFields[5]) ? link(debianRecordUrl(item), 'Debian 수정 패키지 원문') : '',
  ].filter(Boolean);
  let content = rows.length ? rows.map(({field, before, after, at}) => `
    <div class="review-difference">
      <div class="review-difference-heading"><strong>${escape(field)}</strong>
        <small>${at ? `변경 감지 ${escape(date(at))}` : '변경 감지 시각 미확인'}</small></div>
      <dl><div><dt>완료 당시</dt><dd>${renderedValues(before)}</dd></div>
        <div><dt>현재</dt><dd>${renderedValues(after)}</dd></div></dl>
    </div>`).join('') : '<p>완료 당시 정보와 현재 값이 같습니다. 중간에 감지된 변경 내역을 확인하세요.</p>';
  if (!completed) content = '<p>완료 당시의 비교 정보를 읽을 수 없습니다. 현재 정보와 원문을 확인하세요.</p>';
  return `<section class="review-comparison" data-review-comparison>
    <h3>재검토 사유 · 완료 당시와 현재</h3>
    ${times.length ? `<p class="review-baseline">${escape(times.join(' · '))}</p>` : ''}
    ${content}
    ${!rows.length && events.length ? `<details><summary>완료 이후 수집 변경 이력</summary>
      ${events.map((event) => `<div><small>변경 감지 ${escape(date(event.at))}</small>${changeDetails(event)}</div>`).join('')}
    </details>` : ''}
    <div class="version-sources">${sources.join(' ')}</div>
  </section>`;
}

function cveHistory(item) {
  const events = (data.history || []).filter((event) => event.id === item.id);
  if (!events.length) return '';
  return `<details class="cve-history">
    <summary>최근 7일 변경 이력 · ${events.length}건</summary>
    ${events.map((event) => `<article><strong>${historyTypes[event.type]}</strong>
      <time datetime="${escape(event.at)}">${escape(historyDate(event))}</time>${changeDetails(event)}</article>`).join('')}
  </details>`;
}

function metricFreshness(item) {
  const labels = {ok:'', missing:'점수 미제공', unavailable:'수집 실패', stale:'이전 점수'};
  const label = labels[item.epssStatus] || '';
  const scoreDate = item.epss?.date;
  const timestamps = Object.entries(item.sourceTimes || {});
  return `${label || scoreDate ? `<p class="feed-note">EPSS ${escape([label, scoreDate && `기준일 ${scoreDate}`].filter(Boolean).join(' · '))}</p>` : ''}
    ${timestamps.length ? `<details class="metric-freshness"><summary>출처별 확인 시각</summary>
      <ul>${timestamps.map(([name, at]) => `<li>${escape(name)} · ${escape(date(at))}</li>`).join('')}
      ${item.cnaChecked ? `<li>CNA · ${escape(date(item.cnaChecked))}</li>` : ''}</ul></details>` : ''}`;
}

function renderInspector(panel = $('#inspector'), item = selected) {
  if (!item) {
    panel.innerHTML = '<p class="empty">표시할 CVE가 없습니다.</p>';
    return;
  }
  const state = reviewState(item);
  panel.innerHTML = `
    <div class="inspector-heading">
      <div class="eyebrow"><span>${escape(item.id)}</span></div>
      ${panel.id === 'inspector' ? '<button type="button" class="outline inspector-close" data-close-inspector>상세 닫기</button>' : ''}
    </div>
    <h2 tabindex="-1">${escape(cveHeading(item))}</h2>
    ${actionSummary(item)}
    <div class="metrics inspector-metrics">
      <div>CVSS ${item.cvssVersion ? `v${escape(item.cvssVersion)}` : ''}<strong>${Number.isFinite(item.cvss) ? cvss(item) : '미확인'}</strong></div>
      <div>EPSS<strong>${item.epss ? epss(item) : '미확인'}</strong></div><div>KEV<strong>${kev(item)}</strong></div>
    </div>
    ${installedVersionCheck(item)}
    ${debianPackageCheck(item)}
    <div class="review-control">
      <label>내 점검 상태 <select data-review-state aria-label="내 점검 상태">
        ${state === 'recheck' ? '<option value="recheck" selected disabled>재검토 필요</option>' : ''}
        ${['unreviewed', 'investigate', 'done'].map((option) =>
          `<option value="${option}" ${state === option ? 'selected' : ''}>${reviewLabels[option]}</option>`).join('')}
      </select></label>
      <span class="review-save" role="status"></span>
    </div>
    ${reviewComparison(item, state)}
    ${metricFreshness(item)}
    <div class="actions triage-actions">
      <button class="outline" data-guide="check">${icon('shield')}안전한 점검</button>
      <button class="outline" type="button" data-generate-advisory>${icon('doc')}보안공지문 생성</button>
      ${comparisonProducts(item).length ? '<button class="outline" type="button" data-asset-csv>자산 CSV 대조</button>' : ''}
      <button class="outline" type="button" data-share-cve>${icon('doc')}이 CVE 공유</button>
      <button class="outline" type="button" data-copy-cve>${icon('link')}이 CVE 링크 복사</button>
      <span class="copy-status" role="status"></span>
    </div>
    ${cveHistory(item)}
    <div class="technical-details">${technicalDetails(item)}</div>
    <h3>출처 확인</h3>
    <div class="source-list">${evidence(item)}</div>
    <div class="actions"><button class="accent" data-guide="analysis">${icon('search')}CVE 상세</button></div>`;
}

function showPage(name) {
  if (name !== 'cve' && new URL(location.href).searchParams.has('cve')) {
    history.replaceState(null, '', location.pathname);
  }
  const switched = page !== name;
  if (switched) {
    rememberComparisons('#inspector');
    rememberComparisons('#priority-inspector');
    $('#feed').replaceChildren();
  }
  page = name;
  if (switched && page === 'home') renderPriority();
  if (switched && page === 'cve') renderRows();
  $('#priority').hidden = page !== 'home' || priorities.length === 0;
  $('#cve-view').hidden = page !== 'cve';
  $('#overview').hidden = page !== 'home';
  $('#feed').hidden = page === 'cve' || page === 'home';
  $('#page-title').textContent = labels[page];
  $('#open-multi-asset').hidden = !['home', 'cve'].includes(page);
  document.querySelectorAll('[data-page]').forEach((button) => {
    if (button.dataset.page === page) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  if (page === 'home') renderOverview();
  else if (page !== 'cve') renderFeed();
  const section = $(page === 'home' ? '#overview' : page === 'cve' ? '#cve-view' : '#feed');
  section.getAnimations().forEach((animation) => animation.cancel());
  if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
    section.animate([{opacity: .5, transform:'translateY(5px)'}, {opacity:1, transform:'translateY(0)'}],
      {duration:180, easing:'ease-out'});
  }
}

const articleCves = (article) => [...new Set((article.cves || []).filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)))];

function newsCveLinks(ids) {
  return ids.length ? `<div class="news-cves">${ids.map((id) =>
    `<a href="${escape(cveUrl(id))}">${escape(id)} 상세</a>`).join('')}</div>` : '';
}

function groupedNewsArticles(items, heading = 'h3') {
  const groups = new Map();
  for (const item of items) {
    const ids = articleCves(item);
    if (ids.length !== 1 || item.kind === 'advisory') continue;
    const [id] = ids;
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(item);
  }
  return items.map((item) => {
    const [id] = articleCves(item);
    const related = item.kind !== 'advisory' && articleCves(item).length === 1 ? groups.get(id) : undefined;
    if (!related || related.length < 2) return newsArticle(item, heading);
    if (related[0] !== item) return '';
    return `<div class="news-issue">${newsArticle(item, heading)}
      <details><summary>같은 CVE를 다룬 보도 ${related.length - 1}건</summary>
      ${related.slice(1).map((article) => newsArticle(article, heading)).join('')}</details></div>`;
  }).join('');
}

function newsArticle(item, heading = 'h3') {
  let image = '';
  try {
    const address = new URL(item.image);
    if (address.protocol === 'https:' && !address.username && !address.password) {
      image = `<img src="${escape(address.href)}" alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer">`;
    }
  } catch { /* Some feeds publish headlines without images. */ }
  return `<article class="news-item">
    <span class="news-thumb" aria-hidden="true">${icon('news')}${image}</span>
    <div><small>${escape(item.publisher)} · ${escape(date(item.date))}${item.kind === 'aggregated' ? ' · Google 뉴스 경유' : ''}</small>
    <${heading}>${link(item.url, item.title)}</${heading}>
    ${newsCveLinks(articleCves(item))}</div></article>`;
}

document.addEventListener('error', (event) => {
  if (event.target.matches?.('.news-thumb img')) event.target.hidden = true;
}, true);

function overviewHistory() {
  const history = data.history || [];
  const groups = ['kev', 'remediation', 'published'].map((type) => {
    const events = history.filter((event) => event.type === type);
    return `<details class="history-group" ${type === 'kev' ? 'open' : ''}>
      <summary>${historyTypes[type]} <span>${events.length}건</span></summary>
      ${events.map((event) => `<article class="history-event">
        <a href="${escape(cveUrl(event.id))}">${escape(event.id)}</a>
        <span>${escape(event.title)}</span><time datetime="${escape(event.at)}">${escape(historyDate(event))}</time>
        ${changeDetails(event)}
      </article>`).join('') || '<p class="feed-note">최근 7일간 기록된 항목이 없습니다.</p>'}
    </details>`;
  });
  return `<section class="digest digest-cve recent-changes"><h3>최근 7일 변경 이력</h3>${groups.join('')}</section>`;
}

function watchBriefing() {
  const matched = data.cves.filter(watched);
  const eventsById = new Map();
  for (const event of data.history || []) {
    if (!eventsById.has(event.id)) eventsById.set(event.id, []);
    eventsById.get(event.id).push(event);
  }
  const count = (state) => matched.filter((item) => reviewState(item) === state).length;
  const wasPublished = (item) => eventsById.get(item.id)?.some((event) => event.type === 'published');
  const ordered = matched.sort((a, b) => Number(reviewState(b) === 'recheck') - Number(reviewState(a) === 'recheck')
    || (Date.parse(eventsById.get(b.id)?.[0]?.at) || 0) - (Date.parse(eventsById.get(a.id)?.[0]?.at) || 0)
    || comparePriority(a, b));
  const suggested = [...new Set(['Linux Kernel', 'NGINX', 'Fortinet', 'OpenSSL', ...data.cves.map((item) => item.product).filter(Boolean)])];
  return `<section class="digest digest-cve watch-briefing">
    <header><h3>관심 제품 브리핑</h3>${matched.length ? '<button type="button" data-open-view="watch">관심 CVE 전체 →</button>' : ''}</header>
    <form id="watch-form">
      <label for="watch-name">관심 제품</label>
      <input id="watch-name" name="product" required maxlength="70" list="watch-suggestions" placeholder="예: Linux Kernel">
      <datalist id="watch-suggestions">${suggested.map((name) => `<option value="${escape(name)}"></option>`).join('')}</datalist>
      <button type="submit" class="utility">등록</button>
    </form>
    <div class="watch-tags">${preferences.products.map((name, index) =>
      `<button type="button" class="pill" data-remove-watch="${index}" aria-label="${escape(name)} 삭제">${escape(name)} <span aria-hidden="true">×</span></button>`).join('')}</div>
    <p class="watch-feedback" role="status"></p>
    ${preferences.products.length ? `<div class="watch-counts">
      <span>신규 공개 <strong>${matched.filter(wasPublished).length}</strong></span>
      <span>미확인 <strong>${count('unreviewed')}</strong></span>
      <span>영향 확인 필요 <strong>${count('investigate')}</strong></span>
      <span>재검토 필요 <strong>${count('recheck')}</strong></span>
    </div>
    ${ordered.slice(0, 8).map((item) => {
      const events = [...new Set((eventsById.get(item.id) || []).map((event) => historyTypes[event.type]).filter(Boolean))];
      return `<button type="button" class="watch-row" data-cve="${escape(item.id)}">
        <small>${escape(item.id)}</small><span>${escape(item.title)}</span>
        <span class="watch-badges">${events.map((label) => `<span class="pill">${escape(label)}</span>`).join('')}${reviewBadge(item)}</span>
      </button>`;
    }).join('') || '<p class="feed-note">현재 수집 목록에 일치하는 CVE가 없습니다.</p>'}`
    : '<p class="feed-note">담당 제품의 신규 CVE·KEV 등재·패치 변경을 모아볼 수 있습니다. 관심 제품과 점검 상태는 이 브라우저에 저장됩니다.</p>'}
  </section>`;
}

function myWorkRows(items, reviews, drafts, today) {
  const byId = new Map(items.map((item) => [item.id, item]));
  const ids = new Set([...Object.keys(reviews), ...drafts.keys()]);
  return [...ids].flatMap((id) => {
    const item = byId.get(id);
    const draft = drafts.get(id);
    const review = reviews[id];
    const state = item ? reviewState(item) : review?.state === 'done' && remediationSinceReview({id}, review).length
      ? 'recheck' : review?.state;
    if (!draft && !['investigate', 'recheck', 'done'].includes(state)) return [];
    const due = draft?.metadata?.dueDate || '';
    const days = /^\d{4}-\d{2}-\d{2}$/.test(due) ? (Date.parse(due) - Date.parse(today)) / 86400000 : Infinity;
    const changed = Boolean(item && draft?.baseline && remediationHasChanges(item, draft.baseline));
    const urgency = days <= 0 ? 0 : changed || state === 'recheck' ? 1 : days <= 3 ? 2 : 3;
    return [{id, item, draft, review, due, days, state, changed, urgency}];
  }).sort((a,b) => a.urgency - b.urgency || (a.days - b.days || 0)
    || (Date.parse(b.draft?.savedAt || b.review?.completedAt) || 0) - (Date.parse(a.draft?.savedAt || a.review?.completedAt) || 0) || a.id.localeCompare(b.id));
}

function myWork() {
  const today = new Intl.DateTimeFormat('en-CA', {
    timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit',
  }).format(new Date());
  const rows = myWorkRows(data.cves, preferences.reviews, storedAdvisoryDrafts(), today);
  const groups = [
    ['active', '진행 중', rows.filter(({state}) => state !== 'done')],
    ['recheck', '재검토', rows.filter(({state}) => state === 'recheck')],
    ['done', '조치 완료', rows.filter(({state}) => state === 'done')],
    ['draft', '저장한 초안', rows.filter(({draft}) => draft)],
  ];
  const visible = groups.find(([value]) => value === myWorkFilter)[2];
  const render = ({id, item, draft, review, due, days, state, changed}) => {
    const dateLabel = days < 0 ? '기한 지남' : days === 0 ? '오늘 마감' : '조치 기한';
    const completedAt = Date.parse(review?.completedAt);
    const recorded = ['done', 'recheck'].includes(state) ? completedRemediation(review) : null;
    const evidence = (recorded || []).flatMap((value, index) => value.length
      ? [`<li>${escape(remediationFields[index])} · ${escape([value].flat().join(' / '))}</li>`] : []);
    return `<div class="my-work-row">
      <div><small>${escape(id)}</small><strong>${escape(item?.titleKo || item?.title || draft?.title || review?.title || id)}</strong>
        <div class="watch-badges">
          ${draft ? '<span class="pill">저장한 초안</span>' : ''}
          ${state && state !== 'unreviewed' ? `<span class="pill review-${state}">${reviewLabels[state]}</span>` : ''}
          ${changed ? '<span class="pill review-recheck">조치 정보 변경</span>' : ''}
          ${due ? `<span class="pill ${days <= 3 ? 'review-recheck' : ''}">${dateLabel} · ${escape(due)}</span>` : ''}
          ${!item ? '<span class="pill">보관 자료 조회</span>' : ''}
        </div>
        ${Number.isFinite(completedAt) ? `<small>완료 기록 ${escape(date(completedAt))}</small>` : ''}
        ${recorded ? `<details><summary>완료 당시 조치 근거</summary>
          ${evidence.length ? `<ul class="detail-list">${evidence.join('')}</ul>` : '<p>저장된 패치·완화 정보가 없습니다.</p>'}
        </details>` : ''}
      </div>
      <div class="actions">
        ${draft ? `<button type="button" class="outline" data-open-draft="${escape(id)}">초안 이어 쓰기</button>` : ''}
        ${item ? `<button type="button" class="outline" data-cve="${escape(id)}" ${state === 'recheck' ? 'data-open-review' : ''}>${state === 'recheck' ? '변경 확인' : 'CVE 열기'}</button>`
          : `<a class="outline" href="${escape(cveUrl(id))}" data-open-archived="${escape(id)}">보관 CVE 열기</a>`}
      </div>
    </div>`;
  };
  return `<section class="digest digest-cve my-work"><header><h3>내 작업</h3>
    <label for="my-work-filter">작업 보기</label>
    <select id="my-work-filter">${groups.map(([value,label,entries]) =>
      `<option value="${value}" ${value === myWorkFilter ? 'selected' : ''}>${label} · ${entries.length}건</option>`).join('')}</select>
    </header><p class="feed-note" data-work-status role="status"></p>
    ${visible.length ? visible.slice(0, 6).map(render).join('') : '<p class="feed-note">이 상태에 해당하는 저장 작업이 없습니다.</p>'}
    ${visible.length > 6 ? `<details><summary>나머지 ${visible.length - 6}건</summary>${visible.slice(6).map(render).join('')}</details>` : ''}
  </section>`;
}

function renderOverview() {
  const sections = [
    ['issues', '핵심 이슈', data.news.filter((article) => article.kind === 'advisory' || article.cves.length)],
    ['news', '최신 뉴스', data.news.filter((article) => article.kind !== 'advisory')],
    ['korea', '보호나라 공지', data.news.filter((article) => article.kind === 'advisory')],
    ['dark', '다크웹 보도', data.news.filter((article) => article.dark)],
  ];
  const view = $('#overview');
  view.innerHTML = myWork() + watchBriefing() + overviewHistory() + sections.map(([target, title, articles]) => `
    <section class="digest">
      <header><h3>${title}</h3><button data-open="${target}">전체 보기 <span aria-hidden="true">→</span></button></header>
      ${groupedNewsArticles(articles.slice(0, 4), 'h4') || '<p>수집된 항목 없음</p>'}
    </section>`).join('') + `
    <section class="digest digest-cve">
      <header><h3>CVE 우선순위</h3><button data-open="cve">전체 보기 <span aria-hidden="true">→</span></button></header>
      ${[...data.cves].sort(comparePriority).slice(0, 5).map((item) => `
        <button class="overview-cve" data-cve="${escape(item.id)}">
          <small>${escape(item.id)}</small><span>${escape(item.title)}</span><span>CVSS ${cvss(item)} · KEV ${kev(item)}</span>
        </button>`).join('') || '<p>수집된 CVE 없음</p>'}
    </section>`;
}

const newsTopics = [
  ['랜섬웨어·다크웹', /랜섬웨어|다크웹|ransomware|dark.?web/i],
  ['침해·정보유출', /유출|해킹|침해|탈취|breach|data leak|stolen|compromise/i],
  ['취약점·패치', /CVE-|취약점|업데이트 권고|패치|vulnerabilit|patch|zero.day/i],
  ['악성코드·피싱', /악성코드|피싱|malware|phishing|trojan|botnet/i],
  ['AI·클라우드', /인공지능|클라우드|\bAI\b|cloud|챗GPT|ChatGPT/i],
];
const topic = (item) => newsTopics.find(([, pattern]) => pattern.test(item.title))?.[0] || '기타 보안 소식';

function newsForPage() {
  return data.news.filter((article) => {
    if (page === 'korea') return article.korea;
    if (page === 'dark') return article.dark;
    if (page === 'issues') return article.kind === 'advisory' || article.cves.length > 0;
    return true;
  });
}

function filteredNews() {
  const name = $('#feed-source')?.value;
  const terms = ($('#news-query')?.value || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
  return newsForPage().filter((item) => (!name || name === item.publisher)
    && terms.every((term) => `${item.title} ${item.publisher} ${topic(item)} ${articleCves(item).join(' ')}`.toLowerCase().includes(term)));
}

function renderFeed() {
  const before = {source: $('#feed-source')?.value || '', query: $('#news-query')?.value || ''};
  const sourceNames = [...new Set(newsForPage().map((article) => article.publisher))].sort();
  $('#feed').innerHTML = `
    ${page === 'dark' ? '<p class="feed-note">공개 언론의 다크웹·랜섬웨어 관련 보도입니다. 개별 주장은 원문에서 확인하세요.</p>' : ''}
    <div class="news-toolbar">
      <div class="presets" role="group" aria-label="뉴스 보기">
        <button type="button" data-news="recent">최신순</button><button type="button" data-news="topic">키워드별</button>
      </div>
      <label class="search"><input id="news-query" type="search" aria-label="뉴스 키워드" placeholder="뉴스 키워드 검색"></label>
      <label class="feed-filter">매체<select id="feed-source"><option value="">전체 매체</option>${sourceNames.map((name) => `<option>${escape(name)}</option>`).join('')}</select></label>
    </div>
    <div id="articles"></div>`;
  if (sourceNames.includes(before.source)) $('#feed-source').value = before.source;
  $('#news-query').value = before.query;
  const display = () => {
    const items = filteredNews();
    document.querySelectorAll('[data-news]').forEach((button) =>
      button.setAttribute('aria-pressed', String(button.dataset.news === newsMode)));
    const groups = new Map();
    if (newsMode === 'topic') {
      for (const item of items) {
        const name = topic(item);
        if (!groups.has(name)) groups.set(name, []);
        groups.get(name).push(item);
      }
    }
    $('#articles').innerHTML = (newsMode === 'topic' ? [...groups].map(([name, entries]) =>
      `<section class="news-topic"><h3>${escape(name)} <span>${entries.length}건</span></h3>${groupedNewsArticles(entries, 'h4')}</section>`).join('')
      : groupedNewsArticles(items)) || '<p>조건에 맞는 기사가 없습니다.</p>';
  };
  document.querySelectorAll('[data-news]').forEach((button) => button.addEventListener('click', () => {
    newsMode = button.dataset.news;
    display();
  }));
  $('#feed-source').addEventListener('change', display);
  $('#news-query').addEventListener('input', display);
  display();
}

function showGuide(item, mode) {
  if (!item) return;
  guideItem = item;
  const analysis = mode === 'analysis';
  $('#guide-content').innerHTML = `
    <span class="eyebrow">${escape(item.id)}</span>
    <h2 id="guide-title">${analysis ? 'CVE 상세' : '안전한 점검'}</h2>
    <p>${escape(item.title)}</p>
    ${analysis ? `<div class="technical-details">${technicalDetails(item)}</div>
      ${item.vector ? `<code>${escape(item.vector)}</code>` : ''}` : ''}
    <h3>읽기 전용 점검 순서</h3>
    <ol>
      <li>벤더 공지에서 영향 제품·기능·버전과 수정 릴리스를 확인합니다.</li>
      <li>자산 목록 또는 관리 콘솔에서 해당 제품의 버전·빌드와 기능 활성화 여부를 조회합니다.</li>
      <li>벤더 조건과 대조하고, 인터넷 노출이나 비인가 접근 가능성이 있는 자산부터 담당자를 확인합니다.</li>
    </ol>
    <h3>근거</h3>${evidence(item)}`;
  $('#guide').showModal();
}

function selectItem(id) {
  selected = data.cves.find((item) => item.id === id) || (archiveQuery === $('#query').value.trim() ? archiveResults.find((item) => item.id === id) : null);
  renderRows();
}

$('#filters').addEventListener('submit', (event) => {
  event.preventDefault();
  searchArchivedCve($('#query').value.trim());
});
$('#filters').addEventListener('input', () => {
  $('#cve-link-status').hidden = true;
  const id = $('#query').value.trim().toUpperCase();
  if (archiveQuery !== $('#query').value.trim()) {
    archiveQuery = '';
    archiveResults = [];
  }
  renderRows();
  if (/^CVE-\d{4}-\d{4,}$/.test(id) && !data.cves.some((item) => item.id === id)) searchArchivedCve(id);
});
$('#rows').addEventListener('click', (event) => {
  if (event.target.closest('[data-search-archive]')) {
    searchArchivedCve($('#query').value.trim(), true);
    return;
  }
  const button = event.target.closest('.cve-row');
  if (!button) return;
  const id = button.dataset.id;
  selectItem(selected?.id === id ? null : id);
  if (selected && event.detail === 0) $('#inspector h2')?.focus();
  else [...document.querySelectorAll('.cve-row')].find((row) => row.dataset.id === id)?.focus();
});
document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
  view = button.dataset.view;
  renderRows();
}));
document.querySelectorAll('[data-page]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.page)));
function detailsAction(event, item) {
  if (!item) return;
  const button = event.target.closest('[data-guide]');
  const translate = event.target.closest('[data-translate]');
  if (button) showGuide(item, button.dataset.guide);
  if (translate) translateDescription(translate, item);
  const copy = event.target.closest('[data-copy-cve]');
  if (copy) copyCveLink(copy, item);
  const share = event.target.closest('[data-share-cve]');
  if (share) openCveMail(share, item);
  if (event.target.closest('[data-asset-csv]')) openAssetCsv(item);
  const advisory = event.target.closest('[data-generate-advisory]');
  if (advisory) openAdvisory(advisory, item);
  const batch = event.target.closest('[data-export-batch]');
  if (batch) downloadBatchCsv(batch, item);
}

const advisoryTypes = [
  [/\b(?:server.side request forgery|SSRF)\b/i, '서버 측 요청 위조(SSRF)'],
  [/\b(?:cross.site scripting|XSS)\b/i, '크로스 사이트 스크립팅(XSS)'],
  [/\b(?:authentication|auth) bypass\b/i, '인증 우회'],
  [/\bauthorization bypass\b/i, '권한 검사 우회'],
  [/\b(?:remote )?code execution\b/i, '코드 실행'],
  [/\b(?:sensitive )?(?:information|file|data) disclosure\b/i, '정보 노출'],
  [/\bdenial of service\b/i, '서비스 거부'],
  [/\bprivilege escalation\b/i, '권한 상승'],
  [/\b(?:directory|path) traversal\b/i, '경로 탐색'],
  [/\bSQL injection\b/i, 'SQL 삽입'],
  [/\bunrestricted file upload\b/i, '파일 업로드 제한 우회'],
  [/\bopen redirect\b/i, '외부 리다이렉트'],
];

const containsKorean = (value) => /[가-힣]{2}/.test(value || '');
const advisoryCodeIdentifiers = /(?<![\w/])(?:\/[A-Za-z0-9_.:-]+){2,}\b|\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+)+\b|\b[A-Za-z_]\w*::[A-Za-z_]\w*\b|\b[\w-]+\.(?:php|sh|js|xml|conf)\b/g;
const advisoryTerms = [
  [/privilege escalation|\bLPE\b/i, /권한|\bLPE\b/i],
  [/\bcommands?\b/i, /명령|커맨드/],
  [/\b(?:authentication|authorization)\b/i, /인증|인가|권한/],
  [/\b(?:vulnerable|vulnerability)\b/i, /취약|보안 결함/],
  [/\b(?:as root|root privileges|root access)\b/i, /root|루트|관리자/i],
];

function validBrowserTranslation(source, translated) {
  const numbers = (text) => (text.match(/\d+(?:\.\d+)*/g) || []).sort().join(' ');
  const identifiers = source.match(advisoryCodeIdentifiers) || [];
  return containsKorean(translated) && numbers(source) === numbers(translated)
    && identifiers.every((identifier) => translated.includes(identifier))
    && advisoryTerms.every(([english, korean]) => !english.test(source) || korean.test(translated));
}

const koreanText = (source, translations) => containsKorean(source) ? source : translations.get(source);
const englishDescription = (item) => item.descriptionEn || item.description;
const publishedAdvisoryTranslations = (item) =>
  item.advisoryKoRevision === '06f3f7b03a97728560826d7387e1ea25224c65a9' ? item.advisoryKo || [] : [];

function advisoryChanges(comparison) {
  if (!comparison) return [];
  const {rows, events} = comparison;
  return rows.length ? rows : events.flatMap((event) => (event.changes || [])
    .map((change) => ({...change, at:event.at})));
}

function advisoryTranslationSources(item, comparison) {
  const [, solutions, workarounds, requiredAction] = remediationValues(item);
  const changeText = advisoryChanges(comparison).flatMap(({field, before, after}) =>
    [0, 4, 5, 6].some((index) => field === remediationFields[index]) ? [] : [...before, ...after]);
  return [...new Set([
    item.titleKo ? '' : item.title,
    item.descriptionKo ? '' : englishDescription(item),
    ...solutions, ...workarounds, requiredAction, ...changeText,
  ])].filter((text) => text && text !== item.id && !containsKorean(text));
}

function nvdConfigurationEvidence(configurations) {
  if (!configurations?.length) return '<p>수집된 NVD CPE 범위가 없습니다.</p>';
  const render = (node) => {
    const matches = (node.cpeMatch || []).map((entry) => {
      const bounds = [
        ['versionStartIncluding','이상'], ['versionStartExcluding','초과'],
        ['versionEndIncluding','이하'], ['versionEndExcluding','미만'],
      ].flatMap(([key, label]) => entry[key] ? [`${entry[key]} ${label}`] : []);
      const type = entry.vulnerable === true ? '취약 대상 CPE' : '환경 조건 CPE';
      return `<li>${type}${bounds.length ? ` · ${escape(bounds.join(' / '))}` : ''}
        <code>${escape(entry.criteria)}</code></li>`;
    });
    const children = (node.nodes || node.children || []).map(render);
    const operator = {AND:'모두 충족', OR:'하나 이상 충족'}[node.operator];
    const logic = [operator, node.negate ? '조건 부정' : ''].filter(Boolean).join(' · ');
    return `<li>${logic ? `<strong>${escape(logic)}</strong>` : ''}<ul>${[...matches, ...children].join('')}</ul></li>`;
  };
  return `<ul class="nvd-configurations">${configurations.map(render).join('')}</ul>`;
}

function advisoryEvidence(item, translations) {
  const cna = link(cnaRecordUrl(item), 'CNA 레코드');
  const nvd = link(nvdRecordUrl(item), 'NVD 레코드');
  const descriptionLink = item.descriptionEnSource === 'CNA' ? cna
    : item.descriptionEnSource === 'NVD' ? nvd : `${cna} ${nvd}`;
  const vendors = advisoryReferences(item)
    .map((url) => link(url, new URL(url).hostname)).join(' ');
  const ranges = (item.cna?.affected || []).map((product) => `<li><strong>${escape(compareProductLabel(product, item.product))}</strong>
    <ul>${(product.versions || []).map((entry) => `<li>${escape(versionLabel(entry))}</li>`).join('')}
    <li>목록 외 버전 · ${escape(versionStates[product.defaultStatus] || '영향 여부 미확인')}</li></ul></li>`).join('');
  const pair = (label, source, korean, sourceLink) => source ? `<details>
    <summary>${escape(label)} · 원문 대조</summary>
    <div class="evidence-columns"><div><strong>한국어</strong><p>${escape(korean || '수집된 한국어 문장 없음')}</p></div>
    <div><strong>수집 원문</strong><p>${escape(source)}</p></div></div>
    ${sourceLink}</details>` : '';
  const [, solutions, workarounds, requiredAction] = remediationValues(item);
  const overview = englishDescription(item);
  return `
    ${pair('취약점 설명', overview, item.descriptionKo || koreanText(overview, translations), descriptionLink)}
    <h3>영향 버전 및 조건</h3>
    <div class="evidence-columns">
      <div><strong>CNA ${cna}</strong>${ranges ? `<ul>${ranges}</ul>` : '<p>수집된 구조화 범위 없음</p>'}${vendors}</div>
      <div><strong>NVD ${nvd}</strong>${nvdConfigurationEvidence(item.nvdConfigurations)}</div>
    </div>
    <p class="feed-note">CNA의 제품 범위와 NVD의 CPE 적용 조건을 각각 표시합니다. 제품·플랫폼이 같은지 확인한 뒤 범위를 비교하세요.</p>
    <h3>패치 버전</h3>
    ${groupedPatchEvidence(item)}
    <h3>해결책·완화조치</h3>
    ${[...solutions.map((source) => pair('CNA 해결책',source,koreanText(source,translations),cna)),
      ...workarounds.map((source) => pair('CNA 완화책',source,koreanText(source,translations),cna)),
      pair('CISA KEV 권고',requiredAction,koreanText(requiredAction,translations),
        link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`, 'CISA KEV 원문'))].join('')}
    ${vendors ? `<p>벤더 공지·패치 참고 · ${vendors}</p>` : ''}`;
}

function advisoryText(item, {comparison, version, translations = new Map()} = {}) {
  const affected = item.cna?.affected || [];
  const scope = affected.flatMap((product) => [
    `- 제품: ${[product.vendor, product.product].filter(Boolean).join(' / ') || item.product || 'CNA 원문 참조'}`,
    ...(product.platforms?.length ? [`  플랫폼: ${product.platforms.join(', ')}`] : []),
    ...(product.modules?.length ? [`  구성요소: ${product.modules.join(', ')}`] : []),
    ...(product.versions?.length ? product.versions.map((entry) => `  ${versionLabel(entry)}`) : ['  버전 범위 미기재']),
    `  목록 외 버전: ${versionStates[product.defaultStatus] || '영향 여부 미확인'}`,
  ]);
  const conditions = attackConditions(item);
  const metrics = cvssMetrics(item);
  const impacts = (prefix) => [['C', '기밀성'], ['I', '무결성'], ['A', '가용성']].flatMap(([key, label]) => {
    const level = metrics[prefix + key];
    return level === 'H' || level === 'L' ? [`${label} ${level === 'H' ? '높음' : '낮음'}`] : [];
  }).join(' / ');
  const vulnerableImpacts = impacts(item.vector?.startsWith('CVSS:4.0/') ? 'V' : '');
  const subsequentImpacts = impacts('S');
  const networkPath = metrics.AV === 'N' || metrics.AV === 'A';
  const [, solutions, workarounds, requiredAction] = remediationValues(item);
  const patches = patchRecords(item);
  const scopedPatches = patches.filter((patch) => patchProduct(item, patch));
  const cna = cnaRecordUrl(item);
  const nvd = nvdRecordUrl(item);
  const vendors = advisoryReferences(item);
  const changes = [];
  if (comparison) {
    const {completed, events, rows} = comparison;
    changes.push('', '[조치 완료 이후 변경]');
    if (!completed) changes.push('완료 당시 비교 정보를 확인할 수 없습니다.');
    if (!rows.length && events.length) changes.push('수집된 변경 이력 기준입니다.');
    for (const {field, before, after, at} of advisoryChanges(comparison)) {
      const value = (entries) => entries.map((entry) => [0, 4, 5, 6].some((index) => field === remediationFields[index]) ? entry
        : koreanText(entry, translations) || '원문 공지에서 확인').join(' / ') || '기록된 정보 없음';
      changes.push(`- ${field} · 변경 감지 ${at ? date(at) : '시각 미확인'}`,
        `  이전: ${value(before)}`,
        `  이후: ${value(after)}`);
    }
  }
  const product = [...new Set(affected.map((entry) => entry.product).filter(Boolean))].join(', ') || item.product;
  const types = advisoryTypes.filter(([pattern]) => pattern.test(item.title)).map(([, label]) => label);
  const type = types.length ? types.join('·') + ' 취약점' : '보안 취약점';
  const title = item.titleKo || koreanText(item.title, translations) || [product, type].filter(Boolean).join(' ');
  const original = englishDescription(item);
  const description = item.descriptionKo || koreanText(original, translations);
  const publishedTranslations = publishedAdvisoryTranslations(item);
  const publishedTranslation = publishedTranslations.some(([source]) => source === original);
  const descriptionSource = item.descriptionKo ? item.translationSource
    : translations.has(original) ? (publishedTranslation ? '배포 전 기계 번역' : '브라우저 기계 번역') : '';
  const structuredOverview = product && types.length ? `${product}의 ${type}에 대한 공개 공지입니다.`
    : product ? `${product}에 영향을 주는 보안 취약점이 공개됐습니다.` : '공개된 보안 취약점입니다.';
  const localizedAction = (text) => koreanText(text, translations) || '수집한 원문 공지에서 세부 지침을 확인해 주세요.';
  return [
    `[보안공지] ${item.id} · ${title}`,
    '',
    '1. 취약점 개요',
    ...(item.published ? [`- 공개 시각: ${date(item.published)}`] : []),
    description ? `- ${description}${descriptionSource ? ` (${descriptionSource})` : ''}`
      : `- ${structuredOverview} 상세 공격 원리와 영향은 연결된 원문 공지에서 확인해 주세요.`,
    '',
    '2. 주요 위험성',
    `- 심각도: ${Number.isFinite(item.cvss) ? `CVSS ${item.cvssVersion ? `v${item.cvssVersion} ` : ''}${cvss(item)}` : 'CVSS 점수 미확인'}`,
    ...(vulnerableImpacts ? [`- 악용 성공 시 영향(CVSS): ${vulnerableImpacts}`] : []),
    ...(subsequentImpacts ? [`- 후속 시스템 영향(CVSS): ${subsequentImpacts}`] : []),
    `- 실제 악용 근거: ${item.kev === true ? 'CISA KEV 등재' : '이 공지에서 확인된 KEV 등재 근거 없음'}`,
    ...(item.epss && item.epssStatus !== 'stale' ? [`- EPSS: ${epss(item)}${item.epss.date ? ` (${item.epss.date} 기준)` : ''} · 30일 내 악용 확률 추정치`] : []),
    '',
    '3. 영향 범위(버전 및 전제조건)',
    ...(scope.length ? scope : [`- 제품: ${item.product || '미확인'} · 구조화된 영향 버전 미확인`]),
    `- 영향 범위 근거(CNA): ${cna}`,
    ...(item.nvdConfigurations?.length ? [`- NVD 적용 범위(CPE): ${nvd}`] : []),
    ...(conditions.length ? [`- 악용 조건(CVSS): ${conditions.join(' / ')}`] : []),
    '- 제품별 기능 활성화·배포 형태 등 세부 전제조건은 벤더 공지에서 확인해 주세요.',
    '',
    '4. 영향범위 확인 방법',
    '- 자산 목록이나 관리 콘솔에서 제품·에디션, 설치 버전·빌드, 배포판 패키지 릴리스를 조회합니다.',
    '- 벤더 공지에 명시된 기능·모듈·설정의 적용 여부와 대상 경로에 대한 접근 권한을 읽기 전용으로 확인합니다.',
    ...(networkPath ? ['- 방화벽·로드밸런서 정책과 자산 정보를 대조해 영향 인터페이스의 외부 또는 인접망 접근 여부를 확인합니다.'] : []),
    '- 버전·설정 모두를 벤더 영향 범위와 비교합니다. 백포트·자체 빌드는 공급사 공지와 패키지 변경 이력을 확인합니다.',
    ...(version ? ['', '[설치 버전 대조 참고]', version] : []),
    '',
    '5. 조치 방법(패치·완화·보안장비·접근제어)',
    '- 패치: 대상 제품·릴리스의 수정 버전과 적용 절차를 벤더 공지에서 확인합니다.',
    ...(item.officialPatches || []).flatMap(({product,affected,fixed,url,fresh}) => [
      `- ${product} · 영향 ${affected} → 해결 ${fixed}${fresh ? '' : ' (이전 수집 · 최신 원문 확인)'}`,
      `  KISA 보호나라: ${url}`,
    ]),
    ...scopedPatches.flatMap((patch) => [
      `- ${compareProductLabel(patchProduct(item, patch), item.product)} · 수정 버전 ${patch.version}`,
      ...(publicUrl(patch.url) ? [`  근거(${patch.source}): ${publicUrl(patch.url)}`] : []),
    ]),
    ...(patches.some((patch) => !patchProduct(item, patch))
      ? ['- 제품·릴리스와 연결되지 않은 수정 정보는 항목별 근거의 원문에서 확인합니다.'] : []),
    ...(!scopedPatches.length ? [`- 조치 원문 확인: ${vendors[0] || cna}`] : []),
    ...[...new Set(solutions.map(localizedAction))].map((solution) => `  CNA 해결책: ${solution}`),
    ...(workarounds.length ? [...new Set(workarounds.map(localizedAction))].map((workaround) => `- 임시 완화(CNA): ${workaround}`)
      : ['- 임시 완화: 수집된 CNA 권고가 없습니다. 즉시 패치가 어려우면 벤더가 안내한 우회책의 적용 가능 여부를 확인합니다.']),
    ...(solutions.length || workarounds.length ? [`- 해결책·완화조치 근거(CNA): ${cna}`] : []),
    ...(requiredAction ? [`- CISA KEV 조치 권고: ${localizedAction(requiredAction)}`] : []),
    ...(networkPath ? ['- 보안장비 정책: 적용할 규칙은 해당 CVE의 벤더 공지에서 확인합니다.'] : []),
    networkPath ? '- 접근제어: 영향 인터페이스에 불필요한 접근을 차단하고 필요한 출발지·네트워크만 허용합니다.'
      : '- 접근제어: 영향 기능을 이용할 수 있는 계정·서비스 권한을 확인하고 불필요한 권한을 줄입니다.',
    '- 조치 후 설치 버전·설정과 정상 서비스 동작을 재확인합니다.',
    ...changes,
    '',
    '[근거 링크]',
    ...vendors.map((url) => `- 벤더 공지·패치 참고: ${url}`),
    `- CNA: ${cna}`,
    `- NVD: ${nvd}`,
    ...(item.kev === true ? [`- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`] : []),
    `- Security Insight 상세: ${cveUrl(item.id)}`,
    ...(publishedTranslations.length ? [
      '- 배포 전 기계 번역: HPLT·OPUS, Neurora 변환 모델 (CC BY 4.0) https://huggingface.co/Neurora/opus-hplt-en-ko-v2.0',
      '- 기계 번역된 설명과 조치 문장은 배포 전 벤더 원문과 대조해 주세요.',
    ] : []),
  ].join('\n');
}

const advisoryDialog = $('#advisory-dialog');
let advisoryDraft;
const draftMetadata = {internalImpact:'사내 영향 여부', dueDate:'조치 기한', owner:'담당 부서'};
const advisoryStoragePrefix = 'security-insight.advisory-draft.v1.';
const advisoryStorageKey = (item) => advisoryStoragePrefix + item.id;
const draftField = (name) => advisoryDialog.querySelector(`[name="${name}"]`);
const draftStatus = () => advisoryDialog.querySelector('[data-draft-status]');

function loadAdvisoryDraft(item) {
  try {
    const saved = JSON.parse(localStorage.getItem(advisoryStorageKey(item)));
    return typeof saved?.body === 'string' && typeof saved?.generated === 'string' ? saved : null;
  } catch {
    return null;
  }
}

function storedAdvisoryDrafts() {
  const drafts = new Map();
  try {
    for (let index = 0; index < localStorage.length; index++) {
      const key = localStorage.key(index);
      if (!key?.startsWith(advisoryStoragePrefix)) continue;
      const id = key.slice(advisoryStoragePrefix.length);
      if (!/^CVE-\d{4}-\d{4,}$/.test(id)) continue;
      const draft = loadAdvisoryDraft({id});
      if (draft) drafts.set(id, draft);
    }
  } catch { /* Browser storage may be unavailable. */ }
  return drafts;
}

function showAdvisoryDraftChanges() {
  const {item, baseline, offline} = advisoryDraft;
  const area = advisoryDialog.querySelector('[data-advisory-draft-changes]');
  if (offline) {
    area.hidden = true;
    return;
  }
  const {rows, events} = remediationComparison(item, baseline);
  area.hidden = !rows.length && !events.length;
  const currentValues = rows.length ? changeDetails({changes:rows})
    : events.slice(0, 3).map((event) => changeDetails(event)).join('');
  area.querySelector('[data-advisory-change-values]').innerHTML = currentValues;
}

function advisoryPreflightWarnings(item, text, changed, offline) {
  const warnings = [];
  const sections = new Map([...text.matchAll(/^([1-5])\. [^\r\n]*\r?\n([\s\S]*?)(?=^[1-5]\. |^\[근거 링크\]|$(?![\s\S]))/gm)]
    .map((match) => [match[1], match[2].trim()]));
  const missing = ['1','2','3','4','5'].filter((number) => !sections.get(number));
  if (missing.length) warnings.push(`본문이 비어 있거나 제목이 빠진 항목 · ${missing.join(', ')}번`);
  const canonical = (address) => {
    const parsed = publicUrl(address);
    if (!parsed) return '';
    const url = new URL(parsed);
    url.hash = '';
    url.searchParams.sort();
    return url.href;
  };
  const addresses = (section) => new Set((section?.match(/https?:\/\/[^\s<>]+/g) || [])
    .map((value) => canonical(value.replace(/[),.;\]]+$/, ''))).filter(Boolean));
  const scopeLinks = addresses(sections.get('3'));
  const actionLinks = addresses(sections.get('5'));
  const refs = [cnaRecordUrl(item), nvdRecordUrl(item), ...advisoryReferences(item)].map(canonical);
  const patches = patchRecords(item).filter((patch) => patchProduct(item, patch));
  if (!refs.some((url) => scopeLinks.has(url))) warnings.push('영향 범위 항목에 이 CVE의 수집 근거 링크를 추가하세요.');
  if (![...refs, ...patches.map((entry) => canonical(entry.url))].filter(Boolean).some((url) => actionLinks.has(url))) {
    warnings.push('조치 방법 항목에 이 CVE의 패치 또는 완화조치 근거 링크를 추가하세요.');
  }
  const actionText = sections.get('5') || '';
  const writtenVersions = new Set(actionText.split('\n').filter((line) => !line.includes(' · 근거(')
    && /수정 버전|패치|업데이트|업그레이드|upgrade|update/i.test(line))
    .flatMap((line) => line.replace(/https?:\/\/\S+/g, '').match(patchVersionPattern) || []));
  const official = item.officialPatches || [];
  if (official.length && official.some(({product, fixed, url}) =>
    !actionText.split('\n').some((line) => line.includes(product) && line.includes(`해결 ${fixed}`)) || !actionLinks.has(canonical(url)))) {
    warnings.push('본문의 제품별 공식 해결 기준과 KISA 원문 링크를 확인하세요.');
  }
  if (!patches.length && !official.length) warnings.push('수집된 근거에서 제품·릴리스별 수정 버전을 확인하세요.');
  if (patches.length) {
    const matched = patches.filter(({version}) => writtenVersions.has(version));
    if (!matched.length) warnings.push(`조치 방법 본문에 수집된 수정 버전이 없습니다 · ${[...new Set(patches.map(({version}) => version))].join(', ')}`);
    else if (!matched.some(({url}) => actionLinks.has(canonical(url)))) warnings.push('본문에 적힌 수정 버전과 연결되는 근거 링크를 조치 방법에 추가하세요.');
  }
  if (changed) warnings.push('초안 기준 이후 패치 또는 완화 정보가 달라졌습니다. 변경 내용을 확인하고 본문을 갱신하세요.');
  if (offline) warnings.push('현재 수집 목록에 없는 CVE입니다. 공식 원문에서 최신 조치 상태를 확인하세요.');
  return warnings;
}

function renderAdvisoryPreflight() {
  if (!advisoryDraft) return;
  const changed = !advisoryDialog.querySelector('[data-advisory-draft-changes]').hidden;
  const checks = advisoryPreflightWarnings(advisoryDraft.item, advisoryDialog.querySelector('textarea').value,
    changed, advisoryDraft.offline);
  advisoryDialog.querySelector('[data-advisory-preflight-count]').textContent = checks.length ? `· 확인 ${checks.length}건` : '· 추가 확인 항목 없음';
  advisoryDialog.querySelector('[data-advisory-preflight]').innerHTML = checks.length
    ? `<ul>${checks.map((message) => `<li>${escape(message)}</li>`).join('')}</ul>`
    : '<p>본문 항목과 근거 링크가 있습니다. 발송 전 링크의 내용과 문안을 대조하세요.</p>';
}

function saveAdvisoryDraft(acknowledge = false) {
  if (!advisoryDraft) return;
  const {item, generated, comparison, version} = advisoryDraft;
  const baseline = acknowledge ? {reviewedThrough:advisoryDraft.asOf, fingerprint:remediationFingerprint(item)} : advisoryDraft.baseline;
  const saved = {
    body:advisoryDialog.querySelector('textarea').value, generated, baseline, savedAt:new Date().toISOString(),
    title:item.titleKo || item.title,
    metadata:Object.fromEntries(Object.keys(draftMetadata).map((name) => [name, draftField(name).value])),
    comparison:draftField('comparison').checked ? comparison : null,
    version:draftField('version').checked ? version : '',
  };
  try {
    localStorage.setItem(advisoryStorageKey(item), JSON.stringify(saved));
    advisoryDraft.baseline = baseline;
    advisoryDialog.querySelector('[data-remove-advisory]').hidden = false;
    draftStatus().textContent = acknowledge ? '조치 정보 확인 기준을 갱신했습니다. 본문은 편집한 상태로 저장했습니다.'
      : '현재 브라우저에 초안을 저장했습니다.';
    showAdvisoryDraftChanges();
    renderAdvisoryPreflight();
    if (page === 'home') renderOverview();
  } catch {
    draftStatus().textContent = '이 브라우저에 초안을 저장하지 못했습니다. 공지문 복사나 HTML 다운로드를 이용하세요.';
  }
}

function openAdvisory(button, item, offline = false) {
  const result = button?.closest('.inspector')?.querySelector('[data-version-check] .version-result');
  const fields = result?.closest('form').elements;
  const summary = result && !result.hidden ? result.dataset.summary : '';
  const saved = loadAdvisoryDraft(item);
  advisoryDraft = {
    item,
    offline,
    asOf:data.updatedAt,
    baseline: saved?.baseline?.fingerprint && completedRemediation(saved.baseline) ? saved.baseline
      : {reviewedThrough:data.updatedAt, fingerprint:remediationFingerprint(item)},
    generated:saved?.generated,
    comparison:saved?.comparison || (reviewState(item) === 'recheck' ? remediationComparison(item, preferences.reviews[item.id]) : null),
    translations:new Map(publishedAdvisoryTranslations(item)),
    version:saved?.version || (summary ? [
      `대조 제품: ${fields.product.selectedOptions[0].textContent.trim()}`,
      `설치 유형: ${fields.build.selectedOptions[0].textContent.trim()}`,
      summary,
    ].join('\n') : ''),
  };
  for (const name of Object.keys(draftMetadata)) draftField(name).value = saved?.metadata?.[name] || '';
  advisoryDialog.querySelector('textarea').value = saved?.body || '';
  advisoryDialog.querySelector('.advisory-evidence').open = false;
  advisoryDialog.querySelector('.advisory-preflight').open = false;
  advisoryDialog.querySelector('[data-advisory-evidence]').innerHTML = offline
    ? `<p>이 항목은 현재 수집 목록에서 빠져 있습니다. ${link(cnaRecordUrl(item), 'CVE 원문')}</p>`
    : advisoryEvidence(item, advisoryDraft.translations);
  advisoryDialog.querySelector('[data-copy-fallback]').hidden = true;
  for (const key of ['comparison', 'version']) {
    const option = advisoryDialog.querySelector(`[name="${key}"]`);
    option.checked = Boolean(saved?.[key]);
    option.closest('label').hidden = offline || !advisoryDraft[key];
  }
  const translate = advisoryDialog.querySelector('[data-translate-advisory]');
  translate.hidden = offline || !('Translator' in globalThis) || advisoryTranslationSources(item, advisoryDraft.comparison)
    .every((source) => advisoryDraft.translations.has(source));
  translate.disabled = false;
  advisoryDialog.querySelector('[data-translation-status]').textContent = '';
  advisoryDialog.querySelector('[data-offline-draft]').hidden = !offline;
  draftStatus().textContent = saved ? `저장한 초안을 불러왔습니다${Number.isFinite(Date.parse(saved.savedAt)) ? ` · ${date(saved.savedAt)}` : ''}.` : '';
  advisoryDialog.querySelector('[data-remove-advisory]').hidden = !saved;
  if (!saved) updateAdvisory();
  else advisoryDialog.querySelector('[data-copy-status]').textContent = '';
  showAdvisoryDraftChanges();
  renderAdvisoryPreflight();
  advisoryDialog.showModal();
}

function mergeAdvisorySections(text, previous, generated) {
  if (previous === undefined || text === previous) return {text:generated, preserved:false};
  const split = (value) => value.split(/(?=^[1-5]\. |^\[근거 링크\])/m);
  const current = split(text), old = split(previous), next = split(generated);
  if (current.length !== old.length || next.length !== old.length) return {text,preserved:previous !== generated};
  let preserved = false;
  const updated = current.map((section, index) => {
    if (section === old[index]) return next[index];
    if (old[index] !== next[index]) preserved = true;
    return section;
  });
  return {text:updated.join(''), preserved};
}

function updateAdvisory() {
  if (!advisoryDraft) return;
  const {item, comparison, version, translations} = advisoryDraft;
  const generated = advisoryText(item, {
    comparison:advisoryDialog.querySelector('[name="comparison"]').checked ? comparison : null,
    version:advisoryDialog.querySelector('[name="version"]').checked ? version : '',
    translations,
  });
  const preview = advisoryDialog.querySelector('textarea');
  const merged = mergeAdvisorySections(preview.value, advisoryDraft.generated, generated);
  preview.value = merged.text;
  advisoryDraft.generated = generated;
  advisoryDialog.querySelector('[data-copy-status]').textContent = merged.preserved
    ? '직접 수정한 항목에는 자동 변경을 적용하지 않았습니다.' : '';
  renderAdvisoryPreflight();
}

function currentAdvisoryText() {
  const text = advisoryDialog.querySelector('textarea').value.trim();
  const fields = Object.entries(draftMetadata)
    .flatMap(([name, label]) => {
      const value = draftField(name).value.trim();
      return value ? [`- ${label}: ${value}`] : [];
    });
  if (!fields.length) return text;
  const [title, ...body] = text.split('\n');
  return [title, ...fields, ...body].join('\n');
}

function advisoryHtml(text) {
  const [title, ...lines] = text.split('\n');
  const content = lines.filter((line) => line.trim()).map((line) => {
    if (/^[1-5]\. |^\[.+\]$/.test(line)) {
      return `<h2 style="font-size:17px;margin:22px 0 8px;color:#79344e">${escape(line)}</h2>`;
    }
    const match = line.match(/^(.*?)(https?:\/\/\S+)$/);
    const address = match && publicUrl(match[2]);
    const value = address ? `${escape(match[1])}<a href="${escape(address)}" style="color:#783750">${escape(address)}</a>` : escape(line);
    return `<p style="margin:0 0 7px;line-height:1.6;overflow-wrap:anywhere">${value}</p>`;
  }).join('\n');
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${escape(title)}</title></head>
    <body style="margin:24px;color:#242129;background:#fff;font:14px 'Malgun Gothic',Arial,sans-serif">
    <table width="100%" role="presentation" cellspacing="0" cellpadding="0"><tr><td>
    <h1 style="font-size:23px;color:#242129;margin:0 0 14px">${escape(title)}</h1>${content}</td></tr></table></body></html>`;
}

advisoryDialog.querySelector('.advisory-options').addEventListener('change', updateAdvisory);
advisoryDialog.querySelector('#advisory-preview').addEventListener('input', renderAdvisoryPreflight);
advisoryDialog.querySelector('[data-open-advisory-evidence]').addEventListener('click', () => {
  const evidence = advisoryDialog.querySelector('.advisory-evidence');
  evidence.open = true;
  evidence.querySelector('summary').focus();
});
advisoryDialog.querySelector('[data-save-advisory]').addEventListener('click', () => saveAdvisoryDraft());
advisoryDialog.querySelector('[data-remove-advisory]').addEventListener('click', (event) => {
  if (!advisoryDraft) return;
  try {
    localStorage.removeItem(advisoryStorageKey(advisoryDraft.item));
    event.currentTarget.hidden = true;
    draftStatus().textContent = '저장본을 삭제했습니다. 열린 문안은 계속 편집할 수 있습니다.';
    if (page === 'home') renderOverview();
  } catch {
    draftStatus().textContent = '이 브라우저에서 저장본을 삭제하지 못했습니다.';
  }
});
advisoryDialog.querySelector('[data-acknowledge-advisory]').addEventListener('click', () => saveAdvisoryDraft(true));
advisoryDialog.addEventListener('close', () => { advisoryDraft = null; });
advisoryDialog.querySelector('[data-translate-advisory]').addEventListener('click', async (event) => {
  const draft = advisoryDraft;
  if (!draft) return;
  const button = event.currentTarget;
  const status = advisoryDialog.querySelector('[data-translation-status]');
  button.disabled = true;
  status.textContent = '브라우저에서 원문을 번역하고 있습니다.';
  let translator;
  try {
    translator = await Translator.create({sourceLanguage:'en', targetLanguage:'ko'});
    const sources = advisoryTranslationSources(draft.item, draft.comparison);
    for (const source of sources) {
      if (advisoryDraft !== draft) return;
      if (draft.translations.has(source)) continue;
      const translated = (await translator.translate(source)).trim();
      if (validBrowserTranslation(source, translated)) draft.translations.set(source, translated);
    }
    if (advisoryDraft !== draft) return;
    updateAdvisory();
    advisoryDialog.querySelector('[data-advisory-evidence]').innerHTML = advisoryEvidence(draft.item, draft.translations);
    status.textContent = sources.every((source) => draft.translations.has(source))
      ? '원문을 기계 번역했습니다. 버전과 조치 내용은 원문과 대조해 주세요.'
      : '일부 원문을 번역했습니다. 남은 지침은 원문에서 확인해 주세요.';
  } catch {
    if (advisoryDraft !== draft) return;
    updateAdvisory();
    status.textContent = '브라우저 번역을 완료하지 못했습니다. 현재 한국어 초안을 사용할 수 있습니다.';
  } finally {
    translator?.destroy();
    if (advisoryDraft === draft) button.disabled = false;
  }
});
advisoryDialog.querySelector('[data-copy-advisory]').addEventListener('click', async () => {
  const fallback = advisoryDialog.querySelector('[data-copy-fallback]');
  const status = advisoryDialog.querySelector('[data-copy-status]');
  const text = currentAdvisoryText();
  fallback.hidden = true;
  try {
    await navigator.clipboard.writeText(text);
    status.textContent = '보안공지문을 복사했습니다.';
  } catch {
    fallback.value = text;
    fallback.hidden = false;
    fallback.focus();
    fallback.select();
    status.textContent = '선택된 문안을 복사해 주세요.';
  }
});
advisoryDialog.querySelector('[data-export-advisory]').addEventListener('click', () => {
  if (!advisoryDraft) return;
  downloadBlob(new Blob([advisoryHtml(currentAdvisoryText())], {type:'text/html;charset=utf-8'}),
    `${advisoryDraft.item.id}-security-advisory.html`);
});

async function copyCveLink(button, item) {
  const status = button.parentElement.querySelector('.copy-status');
  const url = cveUrl(item.id);
  try {
    await navigator.clipboard.writeText(url);
    status.textContent = '링크를 복사했습니다.';
  } catch {
    const input = document.createElement('input');
    input.type = 'url';
    input.readOnly = true;
    input.value = url;
    input.setAttribute('aria-label', 'CVE 공유 링크');
    status.replaceChildren(input);
    input.select();
  }
}
function syncBatchFields(form) {
  const {batch, version, versions} = form.elements;
  for (const [field, active] of [[version, !batch.checked], [versions, batch.checked]]) {
    field.required = active;
    field.disabled = !active;
    field.closest('label').hidden = !active;
  }
}

for (const panel of [$('#inspector'), $('#priority-inspector')]) {
  panel.addEventListener('submit', (event) => {
    const item = panel.id === 'inspector' ? selected : priorities.find((item) => item.id === prioritySelection);
    if (event.target.matches('[data-debian-check]')) {
      event.preventDefault();
      showDebianVersionResult(event.target, item);
    } else {
      showInstalledVersionResult(event, item);
    }
  });
  panel.addEventListener('input', (event) => {
    const debian = event.target.closest('[data-debian-check]');
    if (debian) debian.querySelector('.version-result').hidden = true;
    const form = event.target.closest('[data-version-check]');
    if (!form || event.target.matches('[data-batch-filter]')) return;
    form.querySelector('.version-result').hidden = true;
    if (event.target === form.elements.batch) syncBatchFields(form);
  });
  panel.addEventListener('change', (event) => {
    if (!event.target.matches('[data-batch-filter]')) return;
    const output = event.target.closest('.version-result');
    const filter = event.target.value;
    let visible = 0;
    for (const row of output.querySelectorAll('[data-version-status]')) {
      const status = row.dataset.versionStatus;
      row.hidden = Boolean(filter) && (filter === 'review' ? ['unaffected', 'fixed'].includes(status) : filter !== status);
      if (!row.hidden) visible++;
    }
    output.querySelector('[data-batch-empty]').hidden = visible > 0;
    output.querySelector('[data-export-batch]').disabled = visible === 0;
  });
}

let guideItem;
$('#inspector').addEventListener('click', (event) => {
  if (event.target.closest('[data-close-inspector]')) {
    const id = selected?.id;
    selectItem(null);
    [...document.querySelectorAll('.cve-row')].find((row) => row.dataset.id === id)?.focus();
    return;
  }
  detailsAction(event, selected);
});
$('#guide').addEventListener('click', (event) => {
  const button = event.target.closest('[data-translate]');
  if (button) translateDescription(button, guideItem);
});
function openCve(id) {
  $('#filters').reset();
  view = 'latest';
  showPage('cve');
  selectItem(id);
  $('#inspector h2')?.focus();
}

function updateReview(event, item) {
  const control = event.target.closest('[data-review-state]');
  if (!control || !item || !['unreviewed', 'investigate', 'done'].includes(control.value)) return;
  const state = control.value;
  if (state === 'unreviewed') delete preferences.reviews[item.id];
  else preferences.reviews[item.id] = {
    state, title:item.titleKo || item.title, reviewedThrough:data.updatedAt, fingerprint:remediationFingerprint(item),
    ...(state === 'done' ? {completedAt:new Date().toISOString()} : {}),
  };
  savePreferences();
  control.querySelector('option[value="recheck"]')?.remove();
  const reviewControl = control.closest('.review-control');
  const oldComparison = reviewControl.nextElementSibling;
  if (oldComparison?.hasAttribute('data-review-comparison')) oldComparison.remove();
  reviewControl.insertAdjacentHTML('afterend', reviewComparison(item, state));
  reviewControl.querySelector('.review-save').textContent =
    canSavePreferences ? '점검 상태를 저장했습니다.' : '브라우저 저장을 사용할 수 없습니다. 현재 탭에서만 적용됩니다.';
  if (page === 'cve' && view === 'recheck') {
    renderRows();
    $('[data-view="recheck"]').focus();
    return;
  }
  const row = [...document.querySelectorAll('.cve-row')].find((entry) => entry.dataset.id === item.id);
  if (row) {
    row.querySelector('.review-badge')?.remove();
    if (state !== 'unreviewed') row.querySelector('.cve-meta').insertAdjacentHTML('beforeend', reviewBadge(item));
  }
  if (page === 'home') renderOverview();
}

$('#inspector').addEventListener('change', (event) => updateReview(event, selected));
$('#priority-inspector').addEventListener('change', (event) =>
  updateReview(event, priorities.find((item) => item.id === prioritySelection)));

$('#overview').addEventListener('submit', (event) => {
  if (event.target.id !== 'watch-form') return;
  event.preventDefault();
  const input = $('#watch-name');
  const name = input.value.trim().replace(/\s+/g, ' ');
  const normalized = normalizeProduct(name);
  if (normalized.length < 2 || preferences.products.some((entry) => normalizeProduct(entry) === normalized)) {
    $('.watch-feedback').textContent = normalized.length < 2 ? '제품명을 두 글자 이상 입력하세요.' : '이미 등록된 제품입니다.';
    return;
  }
  preferences.products.push(name);
  savePreferences();
  rerankWatchedPriorities();
  renderOverview();
  $('.watch-feedback').textContent = canSavePreferences ? `${name} 등록 완료` : '이 탭에 임시로 등록했습니다. 브라우저 저장을 사용할 수 없습니다.';
  $('#watch-name').focus();
});

$('#overview').addEventListener('change', (event) => {
  if (event.target.id !== 'my-work-filter') return;
  myWorkFilter = event.target.value;
  $('.my-work').outerHTML = myWork();
  $('#my-work-filter').focus();
});

$('#overview').addEventListener('click', async (event) => {
  const archived = event.target.closest('[data-open-archived]');
  if (archived && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
    event.preventDefault();
    history.replaceState(null, '', archived.href);
    openIncomingCve(archived.dataset.openArchived);
    return;
  }
  const edit = event.target.closest('[data-open-draft]');
  if (edit) {
    const id = edit.dataset.openDraft;
    let item = data.cves.find((record) => record.id === id);
    if (!item) {
      edit.disabled = true;
      const status = $('[data-work-status]');
      status.textContent = '보관 CVE 근거를 확인하고 있습니다.';
      try {
        item = (await loadArchive())[id];
      } catch { /* A locally saved draft can still be opened without its archive record. */ }
      edit.disabled = false;
      status.textContent = '';
      if (!edit.isConnected || page !== 'home' || $('dialog[open]')) return;
    }
    const saved = loadAdvisoryDraft({id});
    if (saved) openAdvisory(edit, item || {id,title:saved.title || id}, !item);
    return;
  }
  const remove = event.target.closest('[data-remove-watch]');
  if (remove) {
    preferences.products.splice(Number(remove.dataset.removeWatch), 1);
    savePreferences();
    rerankWatchedPriorities();
    renderOverview();
    $('#watch-name').focus();
    return;
  }
  const openView = event.target.closest('[data-open-view]');
  if (openView) {
    $('#filters').reset();
    $('#cve-link-status').hidden = true;
    selected = null;
    view = openView.dataset.openView;
    showPage('cve');
    renderRows();
    $('#query').focus();
    return;
  }
  const section = event.target.closest('[data-open]');
  if (section) showPage(section.dataset.open);
  const item = event.target.closest('[data-cve]');
  if (item) {
    openCve(item.dataset.cve);
    if (item.hasAttribute('data-open-review')) {
      const change = $('#inspector .review-comparison');
      if (change) {
        change.tabIndex = -1;
        change.focus();
      }
    }
  }
});
$('#priority-list').addEventListener('click', (event) => {
  const row = event.target.closest('.priority-row');
  if (!row) return;
  const id = row.dataset.cve;
  prioritySelection = prioritySelection === id ? null : id;
  renderPriority();
  [...document.querySelectorAll('.priority-row')].find((button) => button.dataset.cve === id)?.focus();
});
$('#priority-inspector').addEventListener('click', (event) => {
  detailsAction(event, priorities.find((item) => item.id === prioritySelection));
});

function buildMail() {
  const sections = [];
  const cves = page === 'home' ? priorities : page === 'cve' ? (selected ? [selected] : rowsForFilters()) : [];
  if (cves.length) sections.push(['우선 확인할 CVE', cves.map((item) => ({
    title: `${item.id} · ${item.title}`,
    meta: `CVSS ${cvss(item)} · EPSS ${epss(item)} · KEV ${kev(item)}`,
    url: cveUrl(item.id),
    note: patchRecords(item).length ? '제품·릴리스별 패치 근거는 CVE 상세에서 확인' : '',
  }))]);
  if (page !== 'cve') {
    const articles = (page === 'home' ? data.news.slice(0, 8) : filteredNews()).map((item) => ({
      title:item.title, meta:`${item.publisher} · ${date(item.date)}`, url:item.url,
    }));
    if (articles.length) sections.push([page === 'home' ? '최신 보안 소식' : labels[page], articles]);
  }
  return renderMail(`Security Insight · ${labels[page]}`, sections, location.href);
}

function renderMail(title, sections, address, stamp = `마지막 업데이트 ${date(data.updatedAt)}`) {
  const plain = [title, stamp, ...sections.flatMap(([heading, entries]) =>
    [heading, ...entries.map((item) => [item.title, item.meta, item.note, ...(item.lines || []), publicUrl(item.url)].filter(Boolean).join('\n'))])].join('\n\n');
  const markup = `<!doctype html><html lang="ko"><head><meta charset="utf-8"></head>
    <body style="margin:0;background:#f4f3f5;color:#201e24;font-family:Arial,sans-serif">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="18" style="max-width:680px;margin:auto">
    <tr><td style="background:#241822;color:#fff;border-top:4px solid #ec5998">
    <h1 style="font-size:22px;margin:4px 0">${escape(title)}</h1><p style="margin:4px 0;color:#efc6d8">${escape(stamp)}</p></td></tr>
    ${sections.map(([heading, entries]) => `<tr><td style="background:#fff"><h2 style="font-size:17px">${escape(heading)}</h2>
      ${entries.map((item) => `<div style="border-top:1px solid #e1dee3;padding:10px 0">
      <strong>${link(item.url, item.title) || escape(item.title)}</strong>
      ${item.meta ? `<p style="font-size:12px;color:#595361;margin:5px 0">${escape(item.meta)}${item.note ? ` · ${escape(item.note)}` : ''}</p>` : ''}
      ${item.lines?.length ? `<ul style="margin:5px 0;padding-left:20px;overflow-wrap:anywhere">${item.lines.map((line) => `<li>${escape(line)}</li>`).join('')}</ul>` : ''}</div>`).join('')}
      </td></tr>`).join('')}
    <tr><td style="font-size:12px;color:#595361">${link(address, 'Security Insight 열기')}</td></tr>
    </table></body></html>`;
  return {title, plain, markup, count:sections.reduce((sum, [, items]) => sum + items.length, 0)};
}

const cveMailOptions = $('#cve-mail-options');

function openCveMail(button, item) {
  const panel = button.closest('.inspector');
  const installed = panel.querySelector('[data-version-check] .version-result:not([hidden])');
  const debian = panel.querySelector('[data-debian-check] .version-result:not([hidden])');
  const comparison = [];
  if (installed?.dataset.summary) {
    const fields = installed.closest('form').elements;
    comparison.push({
      title: '제품 버전 대조',
      lines: [
        `대조 제품 · ${fields.product.selectedOptions[0].textContent.trim()}`,
        `설치 유형 · ${fields.build.selectedOptions[0].textContent.trim()}`,
        ...installed.dataset.summary.split('\n'),
      ],
    });
  }
  if (debian?.dataset.summary) {
    comparison.push({title:'Debian 패키지 대조', lines:debian.dataset.summary.split('\n'), url:debianRecordUrl(item)});
  }
  cveMailContext = {item, comparison};
  for (const input of cveMailOptions.querySelectorAll('input')) {
    input.checked = input.defaultChecked;
    input.disabled = input.value === 'comparison' && !comparison.length;
  }
  $('#cve-mail-note').textContent = comparison.length
    ? '대조 결과를 선택하면 입력한 설치 버전도 메일에 포함됩니다.'
    : '이 상세 화면에서 설치 버전을 대조하면 그 결과도 첨부할 수 있습니다.';
  cveMailOptions.hidden = false;
  refreshCveMail();
  $('#email-dialog').showModal();
}

function refreshCveMail() {
  const {item, comparison} = cveMailContext;
  const included = new Set([...cveMailOptions.querySelectorAll('input:checked:not(:disabled)')].map((input) => input.value));
  const address = cveUrl(item.id);
  const sections = [['취약점', [{
    title: item.titleKo || item.title,
    meta: `CVSS ${cvss(item)} · EPSS ${epss(item)} · KEV ${kev(item)}`,
    url: address,
  }]]];
  if (included.has('impact')) {
    const ranges = item.impactScope?.length ? item.impactScope : affectedRanges(item);
    const conditions = attackConditions(item);
    sections.push(['영향 범위 및 전제조건', [{
      title: 'CNA 공식 기록', url:cnaRecordUrl(item),
      lines: [...(ranges.length ? ranges : ['구조화된 영향 범위 미확인']),
        ...(conditions.length ? [`CVSS 기준 · ${conditions.join(' / ')}`] : [])],
    }, {title:'NVD 상세', url:nvdRecordUrl(item)}]]);
  }
  if (included.has('patch')) {
    const kisa = (item.officialPatches || []).map(({product, affected, fixed, url, fresh}) => ({
      title: `${product} · KISA 보호나라`, url,
      lines: [`영향 ${affected} → 해결 ${fixed}${fresh ? '' : ' · 이전 수집 자료'}`],
    }));
    const debianStatus = data.sources?.['Debian Security Tracker'];
    const debian = (item.debianPackages || []).map(({suite, package:pkg, fixed}) => ({
      title: `${suite} / ${pkg} · Debian Security Tracker`, url:debianRecordUrl(item),
      lines: [`수정 패키지 ${fixed}${debianStatus?.state === 'ok' ? '' : ' · 최신 상태는 원문에서 확인'}`],
    }));
    const cna = patchRecords(item).filter((patch) => patch.source === 'CNA 해결책 명시').map((patch) => {
      const product = patchProduct(item, patch);
      return {
        title: product ? compareProductLabel(product, item.product) : 'CNA 해결책 · 적용 제품·릴리스 확인 필요',
        url: patch.url,
        lines: [`수정 버전 ${patch.version}`, patch.text].filter(Boolean),
      };
    });
    const patches = [...kisa, ...debian, ...cna];
    sections.push(['공식 해결 기준', patches.length ? patches : [{
      title: '제품·릴리스별 공식 해결 기준 미확인', url:cnaRecordUrl(item),
    }]]);
  }
  if (included.has('comparison') && comparison.length) sections.push(['이번 설치 버전 대조 결과', comparison]);
  const archived = !data.cves.some((record) => record.id === item.id);
  mailDraft = renderMail(`Security Insight · ${item.id}`, sections, address, archived
    ? '보관 CVE 자료 · 최신 조치는 공식 원문에서 확인' : undefined);
  $('#email-scope').textContent = `${item.id} · 취약점 공유`;
  $('#email-preview').srcdoc = mailDraft.markup;
}

cveMailOptions.addEventListener('change', refreshCveMail);

$('#open-email').addEventListener('click', () => {
  cveMailContext = undefined;
  cveMailOptions.hidden = true;
  mailDraft = buildMail();
  $('#email-scope').textContent = `${labels[page]} · ${mailDraft.count}건`;
  $('#email-preview').srcdoc = mailDraft.markup;
  $('#email-dialog').showModal();
});

function base64(value) {
  const bytes = new TextEncoder().encode(value);
  const blocks = [];
  for (let i = 0; i < bytes.length; i += 0x4000) {
    blocks.push(String.fromCharCode(...bytes.subarray(i, i + 0x4000)));
  }
  return btoa(blocks.join(''));
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

$('#email-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const address = $('#email-address').value.trim();
  if (!mailDraft || !/^[^\s<>,;:"]+@[^\s<>,;:"]+$/.test(address)) return;
  const boundary = `SecurityInsight-${Date.now()}`;
  const wrapped = (value) => base64(value).match(/.{1,76}/g).join('\r\n');
  const sections = [['text/plain', mailDraft.plain], ['text/html', mailDraft.markup]];
  const encodedSubject = mailDraft.title.split(' · ').map((part) => `=?UTF-8?B?${base64(part)}?=`).join(' / ');
  const message = [
    'X-Unsent: 1', `To: ${address}`, `Subject: ${encodedSubject}`, 'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`, '',
    ...sections.flatMap(([type, body]) => [`--${boundary}`, `Content-Type: ${type}; charset=UTF-8`,
      'Content-Transfer-Encoding: base64', '', wrapped(body), '']),
    `--${boundary}--`, '',
  ].join('\r\n');
  downloadBlob(new Blob([message], {type:'message/rfc822'}), cveMailContext ? `${cveMailContext.item.id}.eml` : 'security-insight.eml');
});

function showSourceStatus() {
  const states = {ok:'수집', stale:'이전 데이터', unavailable:'수집 실패', partial:'부분 수집'};
  const entries = Object.entries(data.sources);
  const count = (status) => Number.isInteger(status.expected)
    ? `${status.count}/${status.expected}건` : `${status.count}건`;
  $('#source-status-list').innerHTML = entries.map(([name, status]) =>
    `<li>${escape(name)} <span>${escape(states[status.state] || '미확인')} · ${escape(count(status))}${status.at ? ` · ${escape(date(status.at))}` : ''}</span></li>`).join('');
  const alert = $('#source-alert');
  const delayed = entries.filter(([, status]) => status.state !== 'ok');
  alert.hidden = delayed.length === 0;
  alert.innerHTML = delayed.length ? `
    <strong>일부 출처 수집 미완료</strong>
    <span>${delayed.map(([name, status]) => `${escape(name)} · ${status.state === 'partial'
      ? `부분 수집 ${escape(count(status))}` : status.at ? `마지막 성공 ${escape(date(status.at))}` : '수집 실패'}`).join(' / ')}</span>
    ${data.collection?.lastCompleteAt ? `<span>마지막 전체 수집 ${escape(date(data.collection.lastCompleteAt))}</span>` : ''}
    <a href="#source-status" data-source-status>전체 상태 보기</a>` : '';
}

$('#source-alert').addEventListener('click', (event) => {
  if (event.target.closest('[data-source-status]')) $('#source-status').open = true;
});

function loadArchive() {
  if (!archivePromise) {
    archivePromise = fetch('./cve-archive.json', {cache:'no-cache'}).then((response) => {
      if (!response.ok) throw Error(`CVE archive HTTP ${response.status}`);
      return response.json();
    }).catch((error) => {
      archivePromise = undefined;
      throw error;
    });
  }
  return archivePromise;
}

async function searchArchivedCve(query, focus = false) {
  if (!normalizeProduct(query) || rowsForFilters().some((item) => data.cves.includes(item))) return;
  const id = /^CVE-\d{4}-\d{4,}$/i.test(query) ? query.toUpperCase() : '';
  const inSearch = () => page === 'cve' && $('#query').value.trim().toUpperCase() === query.toUpperCase();
  if (!inSearch()) return;
  const status = $('#cve-link-status');
  status.hidden = false;
  status.textContent = '보관 CVE를 조회하고 있습니다.';
  try {
    const request = loadArchive();
    const archive = await request;
    if (!inSearch() || request !== archivePromise) return;
    const listed = new Set(data.cves.map((item) => item.id));
    archiveQuery = $('#query').value.trim();
    const currentId = selected?.id;
    archiveResults = (id ? [archive[id]].filter(Boolean) : Object.values(archive).filter((item) =>
      !listed.has(item.id) && cveSearchMatch(item, query) !== null)).sort(newest).slice(0, 50);
    if (currentId) selectItem(currentId);
    else renderRows();
    const visible = rowsForFilters();
    if (visible.length) {
      status.textContent = `보관 자료 ${visible.length}건${archiveResults.length === 50 ? ' · 최대 50건 표시' : ''} · 최신 조치는 공식 원문에서 확인하세요.`;
      if (id) {
        selectItem(id);
        if (focus) $('#inspector h2')?.focus();
      } else if (focus) $('#rows .cve-row')?.focus();
      return;
    }
    status.innerHTML = id && !archiveResults.length
      ? `<strong>${escape(id)}</strong> 공개 목록과 보관 자료에 없습니다. ${link(cnaRecordUrl({id}), 'CVE 공식 기록')} ${link(nvdRecordUrl({id}), 'NVD')}`
      : '현재 검색·필터 조건에 맞는 보관 CVE가 없습니다.';
  } catch {
    if (!inSearch()) return;
    status.textContent = '보관 자료를 읽지 못했습니다. 잠시 뒤 다시 검색하세요.';
    renderRows();
  }
}

function openIncomingCve(id) {
  const status = $('#cve-link-status');
  const found = data.cves.some((item) => item.id === id);
  status.hidden = true;
  $('#filters').reset();
  view = 'latest';
  showPage('cve');
  $('#query').value = id;
  selectItem(found ? id : null);
  if (found) $('#inspector h2')?.focus();
  else searchArchivedCve(id, true);
}

const comparisonForms = '[data-version-check], [data-debian-check]';
const comparisonPanels = ['#inspector', '#priority-inspector'];

function isComparisonField(field) {
  if (field.type === 'checkbox') return field.checked;
  return field.value !== '' && !(['product', 'debianPackage'].includes(field.name) && field.options.length === 1);
}

function captureComparisons(panelSelector) {
  const panel = $(panelSelector);
  if (panel.closest('[hidden]')) return [];
  return [...panel.querySelectorAll(comparisonForms)].map((form) => {
    const fields = [...form.elements].filter((field) => field.name && isComparisonField(field));
    return {
      kind:form.matches('[data-debian-check]') ? '[data-debian-check]' : '[data-version-check]',
      fields:fields.map((field) => [field.name, field.type === 'checkbox' ? field.checked
        : ['product', 'debianPackage'].includes(field.name) ? field.selectedOptions[0]?.text : field.value]),
      product:form.elements.product?.selectedOptions[0]?.text,
      open:form.closest('details').open,
      result:!form.querySelector('.version-result').hidden,
      filter:form.querySelector('[data-batch-filter]')?.value || '',
    };
  });
}

function restoreComparisons(panelSelector, comparisons, item) {
  if (!item) return;
  for (const state of comparisons) {
    const form = $(`${panelSelector} ${state.kind}`);
    if (!form) continue;
    form.closest('details').open = state.open;
    const fields = new Map(state.fields);
    if (state.product && fields.size) fields.set('product', state.product);
    let canCompare = true;
    for (const [name, value] of fields) {
      const field = form.elements[name];
      if (field.type === 'checkbox') field.checked = value;
      else if (['product', 'debianPackage'].includes(name)) {
        const matches = [...field.options].filter((option) => option.value !== '' && option.text === value);
        field.value = matches.length === 1 ? matches[0].value : '';
        canCompare &&= matches.length === 1;
      } else field.value = value;
    }
    if (form.elements.batch) syncBatchFields(form);
    if (!state.result || !canCompare) continue;
    if (form.matches('[data-debian-check]')) showDebianVersionResult(form, item);
    else renderInstalledVersionResult(form, item);
    const filter = form.querySelector('[data-batch-filter]');
    if (filter && state.filter) {
      filter.value = state.filter;
      filter.dispatchEvent(new Event('change', {bubbles:true}));
    }
  }
}

function rememberComparisons(panelSelector) {
  const panel = $(panelSelector);
  const id = panel.dataset.comparisonCve;
  const states = captureComparisons(panelSelector);
  if (id && states.length) comparisonWork.set(id, states);
}

function attachComparisons(panelSelector, item) {
  $(panelSelector).dataset.comparisonCve = item.id;
  restoreComparisons(panelSelector, comparisonWork.get(item.id) || [], item);
}

function rerankWatchedPriorities() {
  updatePriorities();
  renderPriority();
}

function updateIsDisruptive() {
  if ($('dialog[open], #priority:not([hidden]) #priority-list [aria-expanded="true"], #cve-view:not([hidden]) #inspector details[open]')) return true;
  if ($('#watch-name')?.value.trim()) return true;
  const active = document.activeElement;
  if (active?.matches('input, select, textarea, summary')) return true;
  return comparisonPanels.some((panel) => captureComparisons(panel).some(({fields}) => fields.length > 0));
}

function showPendingUpdate() {
  $('#apply-update').hidden = !pendingSnapshot;
  $('#refresh-note').textContent = pendingSnapshot
    ? `${date(pendingSnapshot.updatedAt)} 게시 자료가 준비됐습니다. 작업 중인 화면을 유지하고 있습니다.` : '';
  for (const notice of document.querySelectorAll('[data-pending-update]')) notice.hidden = !pendingSnapshot;
}

function applySnapshot(snapshot) {
  const alreadyLoaded = Boolean(data.updatedAt);
  const currentSelection = selected?.id;
  const briefingSelection = prioritySelection;
  rememberComparisons('#inspector');
  rememberComparisons('#priority-inspector');
  const priorityComparisons = comparisonWork.get(briefingSelection) || [];
  const watchDraft = $('#watch-name')?.value;
  const currentProduct = $('#product').value;

  data = snapshot;
  debianLookupPromise = undefined;
  archivePromise = undefined;
  selected = data.cves.find((item) => item.id === currentSelection) || archiveResults.find((item) => item.id === currentSelection) || null;
  updatePriorities();
  const stamp = $('#freshness');
  stamp.dateTime = data.updatedAt;
  stamp.textContent = date(data.updatedAt);
  updateClock(data.updatedAt);
  $('#open-email').disabled = false;
  $('#open-multi-asset').disabled = data.cves.length === 0;
  showSourceStatus();
  const products = [...new Set(data.cves.map((item) => item.product).filter(Boolean))].sort();
  $('#product').replaceChildren(new Option('모든 제품', ''), ...products.map((product) => new Option(product, product)));
  if (products.includes(currentProduct)) $('#product').value = currentProduct;
  renderPriority();
  renderRows();
  if (!alreadyLoaded && incomingCve) openIncomingCve(incomingCve);
  else if (page === 'home') {
    renderOverview();
    if (watchDraft) $('#watch-name').value = watchDraft;
  } else if (page !== 'cve') renderFeed();
  else if (archiveQuery && $('#query').value.trim() === archiveQuery) searchArchivedCve(archiveQuery);

  if (page === 'home' && briefingSelection && !prioritySelection
    && priorityComparisons.some(({fields}) => fields.length)
    && data.cves.some(({id}) => id === briefingSelection)) {
    openCve(briefingSelection);
  }
}

function receiveSnapshot(snapshot, manual) {
  const note = $('#refresh-note');
  const incoming = Date.parse(snapshot.updatedAt);
  if (!Number.isFinite(incoming)) throw Error('Invalid snapshot timestamp');
  const newestKnown = pendingSnapshot?.updatedAt || data.updatedAt;
  if (newestKnown && incoming <= Date.parse(newestKnown)) {
    if (pendingSnapshot && !updateIsDisruptive()) applyPendingSnapshot();
    else if (pendingSnapshot) showPendingUpdate();
    else if (manual) note.textContent = '현재 게시된 최신 데이터를 보고 있습니다.';
    return;
  }
  const alreadyLoaded = Boolean(data.updatedAt);
  if (alreadyLoaded && updateIsDisruptive()) {
    pendingSnapshot = snapshot;
    showPendingUpdate();
    return;
  }
  pendingSnapshot = undefined;
  applySnapshot(snapshot);
  showPendingUpdate();
  if (manual || alreadyLoaded) note.textContent = '새 데이터가 반영됐습니다.';
}

function applyPendingSnapshot() {
  if (!pendingSnapshot || $('dialog[open]')) return;
  const snapshot = pendingSnapshot;
  pendingSnapshot = undefined;
  applySnapshot(snapshot);
  showPendingUpdate();
  $('#refresh-note').textContent = '새 데이터가 반영됐습니다.';
}

async function load(manual = false) {
  if (loading) return;
  loading = true;
  const reload = $('#refresh-data');
  const note = $('#refresh-note');
  reload.disabled = true;
  if (manual && !pendingSnapshot) note.textContent = '새 데이터를 확인하고 있습니다.';
  try {
    const response = await fetch('./data.json', {cache:'no-cache'});
    if (!response.ok) throw Error(`Snapshot HTTP ${response.status}`);
    receiveSnapshot(await response.json(), manual);
  } catch (error) {
    if (!data.updatedAt) $('#freshness').textContent = '수집 데이터 로딩 실패';
    if (manual && !pendingSnapshot) note.textContent = '갱신을 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.';
    console.error(error);
  } finally {
    reload.disabled = false;
    loading = false;
  }
}

$('#apply-update').addEventListener('click', () => {
  if (!pendingSnapshot || $('dialog[open]')) return;
  applyPendingSnapshot();
  $('#refresh-data').focus();
});
$('#refresh-data').addEventListener('click', () => load(true));
load();
setInterval(() => {
  if (!document.hidden) load();
}, 60000);
