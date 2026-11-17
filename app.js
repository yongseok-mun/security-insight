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
const link = (address, label) => {
  try {
    const parsed = new URL(address);
    if (['https:', 'http:'].includes(parsed.protocol) && !parsed.username && !parsed.password) {
      return `<a href="${escape(parsed.href)}" target="_blank" rel="noopener noreferrer">${escape(label)} ↗</a>`;
    }
  } catch { /* The upstream record may have no URL. */ }
  return '';
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
let priorities = [];
let newsMode = 'recent';
let mailDraft;
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

function remediationFingerprint(item) {
  return JSON.stringify([
    [...new Set([...(item.fixes || []), ...(item.describedFixes || [])])].sort(),
    [...new Set(item.cna?.solutions || [])].sort(),
    [...new Set(item.cna?.workarounds || [])].sort(),
    item.requiredAction || '',
  ]);
}

function reviewState(item) {
  const review = preferences.reviews[item.id];
  if (review?.state === 'investigate') return 'investigate';
  if (review?.state !== 'done') return 'unreviewed';
  const changed = (data.history || []).some((event) => event.id === item.id && event.type === 'remediation'
    && Date.parse(event.at) > Date.parse(review.reviewedThrough));
  return changed || review.fingerprint !== remediationFingerprint(item) ? 'recheck' : 'done';
}

function reviewBadge(item) {
  const state = reviewState(item);
  return `<span class="pill review-badge review-${state}">${reviewLabels[state]}</span>`;
}

function rowsForFilters() {
  const terms = $('#query').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const product = $('#product').value;
  const rows = data.cves.filter((item) => {
    const text = [item.id, item.title, item.product, ...item.fixes, item.description].join(' ').toLowerCase();
    return terms.every((term) => text.includes(term)) && (!product || item.product === product)
      && (view !== 'watch' || watched(item))
      && (view !== 'recheck' || reviewState(item) === 'recheck')
      && (view !== 'kev' || item.kev === true)
      && (view !== 'critical' || item.cvss >= 9)
      && (view !== 'epss' || item.epss != null);
  });
  if (view === 'epss') return rows.sort((a, b) => b.epss.score - a.epss.score || newest(a, b));
  if (view === 'kev') return rows.sort((a, b) => (b.kevDate || '').localeCompare(a.kevDate || '') || newest(a, b));
  return rows.sort(newest);
}

function renderPriority() {
  const panel = $('#priority-inspector');
  const item = priorities.find((entry) => entry.id === prioritySelection);
  prioritySelection = item?.id || null;
  panel.hidden = true;
  $('#priority').append(panel);
  $('#priority').hidden = page !== 'home' || priorities.length === 0;
  $('#priority-list').innerHTML = priorities.map((entry) => `
    <li><button type="button" class="priority-row" data-cve="${escape(entry.id)}"
      aria-expanded="${entry === item}" aria-controls="priority-inspector">
      <span class="priority-copy"><span>${escape(entry.id)}</span><strong>${escape(entry.title)}</strong></span>
      <span class="cve-meta">
        ${entry.kev === true ? '<span class="pill kev">KEV</span>' : ''}
        <span class="pill">CVSS ${cvss(entry)}</span>
        <span class="pill">EPSS ${epss(entry)}</span>
      </span>
      <span class="priority-detail">${entry === item ? '상세 닫기' : '상세 보기'} <span aria-hidden="true">⌄</span></span>
    </button></li>`).join('');
  if (item) {
    renderInspector(panel, item);
    $('#priority-list [aria-expanded="true"]').after(panel);
    panel.hidden = false;
  }
}

// The Pages workflow starts at minute 17 on every even UTC hour.
function updateClock(stamp) {
  clearInterval(clockTimer);
  const collected = new Date(stamp);
  const next = new Date(collected);
  next.setUTCHours(Math.floor(next.getUTCHours() / 2) * 2, 17, 0, 0);
  if (next <= collected) next.setUTCHours(next.getUTCHours() + 2);
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

function renderRows() {
  const records = rowsForFilters();
  if (!records.includes(selected)) selected = null;
  const inspector = $('#inspector');
  inspector.hidden = true;
  $('#cve-view').append(inspector);

  $('#rows').innerHTML = records.map((item) => {
    const active = item === selected;
    const severity = item.cvss >= 9 ? 'critical' : item.cvss >= 7 ? 'high' : item.cvss >= 4 ? 'medium' : '';
    return `<li>
      <button class="cve-row" type="button" data-id="${escape(item.id)}"
        aria-expanded="${active}" ${active ? 'aria-controls="inspector"' : ''}>
        <span class="cve-id">${escape(item.id)}</span>
        <span class="cve-description"><strong>${escape(item.title)}</strong>${item.product ? `<small>${escape(item.product)}</small>` : ''}</span>
        <span class="cve-meta">
          <span class="pill ${severity}">CVSS ${cvss(item)}</span>
          ${item.kev === true ? '<span class="pill kev">KEV</span>' : ''}
          ${item.fixes.length ? '<span class="pill fix">수정 버전</span>' : ''}
          ${reviewState(item) !== 'unreviewed' ? reviewBadge(item) : ''}
          ${view === 'epss' ? `<span class="pill">EPSS ${epss(item)}</span>` : ''}
          ${item.published ? `<time datetime="${escape(item.published)}">${escape(date(item.published))}</time>` : ''}
        </span>
      </button>
    </li>`;
  }).join('') || '<li class="empty">조건에 맞는 CVE가 없습니다.</li>';

  $('#count').textContent = `총 ${records.length}건`;
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.view === view));
  });
  if (selected) {
    renderInspector();
    $('#rows [aria-expanded="true"]').after(inspector);
    inspector.hidden = false;
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
    + item.notices.map((notice) => `<p class="evidence-link">${link(notice.url, 'KISA · ' + notice.title)}</p>`).join('');
}

const versionStates = {affected:'영향받음', unaffected:'영향 없음', unknown:'영향 여부 미확인'};

function versionLabel(entry) {
  const lower = entry.version === '0' && (entry.lessThan || entry.lessThanOrEqual)
    ? '최초 버전부터' : `${entry.version} 이상`;
  const range = entry.lessThan ? `${lower} · ${entry.lessThan} 미만`
    : entry.lessThanOrEqual ? `${lower} · ${entry.lessThanOrEqual} 이하` : entry.version;
  const transitions = (entry.changes || []).map((change) =>
    `${change.at}부터 ${versionStates[change.status] || '상태 확인 필요'}`);
  return [`${versionStates[entry.status] || '미확인'}: ${range}`, ...transitions].join(' · ');
}

function attackConditions(item) {
  if (!/^CVSS:(3\.[01]|4\.0)\//.test(item.vector || '')) return [];
  const values = Object.fromEntries(item.vector.split('/').slice(1).map((part) => part.split(':')));
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

function installedVersionCheck(item) {
  const products = item.cna?.affected || [];
  const cnaLink = link(`https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`, 'CNA 원문');
  const vendorLinks = (item.cna?.references || []).map((url) => link(url, '벤더 공지')).filter(Boolean);
  return `
    <details class="version-check">
      <summary>설치 버전·영향 조건 대조</summary>
      ${products.length ? `
      <form data-version-check>
        <p class="version-hint">입력값은 이 화면에서만 사용합니다. 제품과 설치 버전은 공지에 쓰인 형식으로 입력하세요.</p>
        <div class="version-fields">
          <label>공지 제품<select name="product" required>
            ${products.length > 1 ? '<option value="">제품·플랫폼 선택</option>' : ''}
            ${products.map((product, index) => `<option value="${index}">${escape(compareProductLabel(product, item.product))}</option>`).join('')}
          </select></label>
          <label>설치 버전<input name="version" required maxlength="100" placeholder="예: 3.4.1" spellcheck="false" autocomplete="off"></label>
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

function showInstalledVersionResult(event, item) {
  const form = event.target.closest('[data-version-check]');
  if (!form) return;
  event.preventDefault();
  const fields = form.elements;
  const product = item?.cna?.affected?.[Number(fields.product.value)];
  const version = fields.version.value.trim();
  if (!product || fields.product.value === '' || !version) return;
  const upstream = fields.build.value === 'upstream';
  const result = upstream ? evaluateInstalledVersion(product, version) : null;
  const conditionNotes = [
    product.platforms?.length ? `플랫폼 · ${product.platforms.join(', ')}` : '',
    product.modules?.length ? `구성요소 · ${product.modules.join(', ')}` : '',
    ...attackConditions(item),
  ].filter(Boolean);
  const fixes = [...new Set([...(item.fixes || []), ...(item.describedFixes || [])])];
  let headline = '추가 확인 필요';
  let explanation = '벤더 공지에서 제품 에디션·기능 설정과 영향 조건을 확인하세요.';
  if (!upstream) {
    explanation = '배포판·백포트·자체 빌드는 설치 패키지 릴리스와 해당 공급사의 보안 공지로 확인하세요.';
    if (!fields.build.value) explanation = '설치 유형을 선택하면 공지 범위와 대조할 수 있습니다.';
  } else if (result.status === 'unaffected') {
    headline = '공지상 해당 버전은 영향 없음';
    explanation = '선택한 제품·플랫폼의 공지 범위를 기준으로 확인했습니다.';
  } else if (result.status === 'affected' && fields.conditions.value === 'met') {
    headline = '공지상 영향 조건에 해당';
    explanation = '확인한 조건과 설치 버전을 기준으로 패치 또는 완화조치를 검토하세요.';
  } else if (result.status === 'affected' && fields.conditions.value === 'not-met') {
    explanation = '버전은 영향 범위에 해당합니다. 확인한 필수 조건과 다른 악용 경로가 있는지 공지에서 다시 대조하세요.';
  }
  const output = form.querySelector('.version-result');
  output.innerHTML = `
    <strong>${headline}</strong><p>${explanation}</p>
    ${result ? `<p>버전 근거 · ${escape(result.reason)}</p>` : ''}
    ${result?.status === 'unknown' && product.versions?.length ? `<details>
      <summary>CNA 버전 범위 직접 대조</summary>
      <ul class="detail-list">${product.versions.map((entry) => `<li>${escape(versionLabel(entry))}</li>`).join('')}</ul>
    </details>` : ''}
    ${conditionNotes.length ? `<p>제품·CVSS 참고 조건 · ${escape(conditionNotes.join(' / '))}</p>` : ''}
    <p>수정 정보 · ${escape(fixes.join(', ') || item.cna?.solutions?.[0] || '확인된 수정 버전 없음 · 원문 공지 참조')}</p>`;
  output.hidden = false;
}

function bilingual(item) {
  const english = item.descriptionEn || item.description;
  const korean = item.descriptionKo;
  const showMachine = english && !korean && 'Translator' in globalThis;
  return `
    <div class="bilingual">
      <div><h4>한국어${korean && item.translationSource ? ` <small>${escape(item.translationSource)}</small>` : ''}</h4>
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
    ${item.fixes.length ? `<p>${escape(item.fixes.join(', '))} <small>· cve.now 수정 버전 정보</small></p>` : ''}
    ${item.describedFixes?.length ? `<p>${escape(item.describedFixes.join(', '))} <small>· 취약점 설명에 명시된 수정 버전</small></p>` : ''}
    ${!item.fixes.length && !item.describedFixes?.length && !cna.solutions?.length ? '<p>패치 버전 미확인</p>' : ''}
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
    const translated = await translator.translate(item.descriptionEn || item.description);
    answer.textContent = translated;
    button.textContent = '기계 번역 · 원문 대조 필요';
  } catch {
    answer.textContent = '이 브라우저에서 번역을 불러오지 못했습니다. 아래 영문을 확인하세요.';
    button.disabled = false;
  } finally {
    translator?.destroy();
  }
}

function actionSummary(item) {
  const affected = item.cna?.affected || [];
  const ranges = affected.flatMap((product) => product.versions
    .filter((entry) => entry.status === 'affected' || (entry.changes || []).some((change) => change.status === 'affected'))
    .map((entry) => `${product.product || item.product || '제품 미확인'} · ${versionLabel(entry)}`));
  const conditions = attackConditions(item);
  const fixes = [...new Set([...item.fixes, ...(item.describedFixes || [])])];
  const platforms = [...new Set(affected.flatMap((product) => product.platforms || []))];
  const modules = [...new Set(affected.flatMap((product) => product.modules || []))];
  const firstCheck = [
    '설치 버전·빌드를 영향 범위와 대조하세요.',
    platforms.length ? `대상 플랫폼 · ${platforms.join(', ')}.` : '',
    modules.length ? `구성요소 사용 여부 · ${modules.join(', ')}.` : '',
    conditions.includes('접근 경로 · 네트워크') ? '관리 대상 서비스의 접근 가능 경로도 확인하세요.' : '',
  ].filter(Boolean).join(' ');
  const visibleRanges = ranges.slice(0, 3).map(escape).join('<br>');
  return `
    <section class="action-summary">
      <h3>조치 요약</h3>
      <dl>
        <div><dt>영향 버전 <small>CNA</small></dt><dd>${visibleRanges || '명시된 영향 버전 미확인. 아래 영향 범위와 공지를 확인하세요.'}${ranges.length > 3 ? `<br><small>외 ${ranges.length - 3}개 범위 · 아래 영향 범위에 전체 표시</small>` : ''}</dd></div>
        <div><dt>성립 조건 <small>CVSS 기준</small></dt><dd>${escape(conditions.length ? conditions.join(' / ') : '구조화된 조건 미확인')}${conditions.length ? '<br><small>제품별 설정·기능 조건은 아래 설명과 원문 참조</small>' : ''}</dd></div>
        <div><dt>수정 버전</dt><dd>${escape(fixes.length ? fixes.join(', ') : item.cna?.solutions?.[0] || '수정 버전 미확인 · 벤더 공지 참조')}</dd></div>
        <div><dt>첫 점검</dt><dd>${escape(firstCheck)}</dd></div>
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
  panel.innerHTML = `
    <div class="eyebrow"><span>${escape(item.id)}</span>${item.kev === true ? '<span class="pill critical">KEV 등재</span>' : ''}</div>
    <h2 tabindex="-1">${escape(item.title)}</h2>
    <div class="metrics">
      <div>CVSS ${item.cvssVersion ? `v${escape(item.cvssVersion)}` : ''}<strong>${cvss(item)}</strong></div>
      <div>EPSS<strong>${epss(item)}</strong></div><div>KEV<strong>${kev(item)}</strong></div>
    </div>
    ${actionSummary(item)}
    ${installedVersionCheck(item)}
    <div class="review-control">
      <label>내 점검 상태 <select data-review-state aria-label="내 점검 상태">
        ${reviewState(item) === 'recheck' ? '<option value="recheck" selected disabled>재검토 필요</option>' : ''}
        ${['unreviewed', 'investigate', 'done'].map((state) =>
          `<option value="${state}" ${reviewState(item) === state ? 'selected' : ''}>${reviewLabels[state]}</option>`).join('')}
      </select></label>
      <span class="review-note"${reviewState(item) === 'recheck' ? '' : ' hidden'}>완료 처리 후 패치·완화 정보가 변경됐습니다.</span>
      <span class="review-save" role="status"></span>
    </div>
    ${metricFreshness(item)}
    <div class="actions triage-actions">
      <button class="outline" data-guide="check">${icon('shield')}안전한 점검</button>
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
  if (page !== name) $('#feed').replaceChildren();
  page = name;
  $('#priority').hidden = page !== 'home' || priorities.length === 0;
  $('#cve-view').hidden = page !== 'cve';
  $('#overview').hidden = page !== 'home';
  $('#feed').hidden = page === 'cve' || page === 'home';
  $('#page-title').textContent = labels[page];
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
    <${heading}>${link(item.url, item.title)}</${heading}></div></article>`;
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

function renderOverview() {
  const sections = [
    ['issues', '핵심 이슈', data.news.filter((article) => article.kind === 'advisory' || article.cves.length)],
    ['news', '최신 뉴스', data.news.filter((article) => article.kind !== 'advisory')],
    ['korea', '보호나라 공지', data.news.filter((article) => article.kind === 'advisory')],
    ['dark', '다크웹 보도', data.news.filter((article) => article.dark)],
  ];
  const view = $('#overview');
  view.innerHTML = watchBriefing() + overviewHistory() + sections.map(([target, title, articles]) => `
    <section class="digest">
      <header><h3>${title}</h3><button data-open="${target}">전체 보기 <span aria-hidden="true">→</span></button></header>
      ${articles.slice(0, 4).map((article) => newsArticle(article, 'h4')).join('') || '<p>수집된 항목 없음</p>'}
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
    && terms.every((term) => `${item.title} ${item.publisher} ${topic(item)}`.toLowerCase().includes(term)));
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
      `<section class="news-topic"><h3>${escape(name)} <span>${entries.length}건</span></h3>${entries.map((item) => newsArticle(item)).join('')}</section>`).join('')
      : items.map((item) => newsArticle(item)).join('')) || '<p>조건에 맞는 기사가 없습니다.</p>';
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
  selected = data.cves.find((item) => item.id === id);
  renderRows();
}

$('#filters').addEventListener('submit', (event) => event.preventDefault());
$('#filters').addEventListener('input', () => {
  $('#cve-link-status').hidden = true;
  renderRows();
});
$('#rows').addEventListener('click', (event) => {
  const button = event.target.closest('.cve-row');
  if (!button) return;
  const id = button.dataset.id;
  selectItem(selected?.id === id ? null : id);
  [...document.querySelectorAll('.cve-row')].find((row) => row.dataset.id === id)?.focus();
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
}

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
for (const panel of [$('#inspector'), $('#priority-inspector')]) {
  panel.addEventListener('submit', (event) => showInstalledVersionResult(event,
    panel.id === 'inspector' ? selected : priorities.find((item) => item.id === prioritySelection)));
  panel.addEventListener('input', (event) => {
    const form = event.target.closest('[data-version-check]');
    if (form) form.querySelector('.version-result').hidden = true;
  });
}

let guideItem;
$('#inspector').addEventListener('click', (event) => detailsAction(event, selected));
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
    state, reviewedThrough:data.updatedAt, fingerprint:remediationFingerprint(item),
  };
  savePreferences();
  control.querySelector('option[value="recheck"]')?.remove();
  control.parentElement.parentElement.querySelector('.review-note').hidden = true;
  control.parentElement.parentElement.querySelector('.review-save').textContent =
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
  renderOverview();
  $('.watch-feedback').textContent = canSavePreferences ? `${name} 등록 완료` : '이 탭에 임시로 등록했습니다. 브라우저 저장을 사용할 수 없습니다.';
  $('#watch-name').focus();
});

$('#overview').addEventListener('click', (event) => {
  const remove = event.target.closest('[data-remove-watch]');
  if (remove) {
    preferences.products.splice(Number(remove.dataset.removeWatch), 1);
    savePreferences();
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
  if (item) openCve(item.dataset.cve);
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
    note: item.fixes.length ? `수정 버전 ${item.fixes.join(', ')}` : '',
  }))]);
  if (page !== 'cve') {
    const articles = (page === 'home' ? data.news.slice(0, 8) : filteredNews()).map((item) => ({
      title:item.title, meta:`${item.publisher} · ${date(item.date)}`, url:item.url,
    }));
    if (articles.length) sections.push([page === 'home' ? '최신 보안 소식' : labels[page], articles]);
  }
  const title = `Security Insight · ${labels[page]}`;
  const stamp = `마지막 업데이트 ${date(data.updatedAt)}`;
  const plain = [title, stamp, ...sections.flatMap(([heading, entries]) =>
    [heading, ...entries.map((item) => [item.title, item.meta, item.note, item.url].filter(Boolean).join('\n'))])].join('\n\n');
  const markup = `<!doctype html><html lang="ko"><head><meta charset="utf-8"></head>
    <body style="margin:0;background:#f4f3f5;color:#201e24;font-family:Arial,sans-serif">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="18" style="max-width:680px;margin:auto">
    <tr><td style="background:#241822;color:#fff;border-top:4px solid #ec5998">
    <h1 style="font-size:22px;margin:4px 0">${escape(title)}</h1><p style="margin:4px 0;color:#efc6d8">${escape(stamp)}</p></td></tr>
    ${sections.map(([heading, entries]) => `<tr><td style="background:#fff"><h2 style="font-size:17px">${escape(heading)}</h2>
      ${entries.map((item) => `<div style="border-top:1px solid #e1dee3;padding:10px 0">
      <strong>${link(item.url, item.title) || escape(item.title)}</strong>
      <p style="font-size:12px;color:#595361;margin:5px 0">${escape(item.meta)}${item.note ? ` · ${escape(item.note)}` : ''}</p></div>`).join('')}
      </td></tr>`).join('')}
    <tr><td style="font-size:12px;color:#595361">${link(location.href, 'Security Insight 열기')}</td></tr>
    </table></body></html>`;
  return {title, plain, markup, count:sections.reduce((sum, [, items]) => sum + items.length, 0)};
}

$('#open-email').addEventListener('click', () => {
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
  const url = URL.createObjectURL(new Blob([message], {type:'message/rfc822'}));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'security-insight.eml';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
});

function showSourceStatus() {
  const states = {ok:'수집', stale:'이전 데이터', unavailable:'수집 실패'};
  const entries = Object.entries(data.sources);
  $('#source-status-list').innerHTML = entries.map(([name, status]) =>
    `<li>${escape(name)} <span>${escape(states[status.state] || '미확인')} · ${status.count}건${status.at ? ` · ${escape(date(status.at))}` : ''}</span></li>`).join('');
  const alert = $('#source-alert');
  const delayed = entries.filter(([, status]) => status.state === 'stale' || status.state === 'unavailable');
  alert.hidden = delayed.length === 0;
  alert.innerHTML = delayed.length ? `
    <strong>일부 출처 지연</strong>
    <span>${delayed.map(([name, status]) => `${escape(name)} · ${status.at ? `마지막 성공 ${escape(date(status.at))}` : '수집 실패'}`).join(' / ')}</span>
    <a href="#source-status" data-source-status>전체 상태 보기</a>` : '';
}

$('#source-alert').addEventListener('click', (event) => {
  if (event.target.closest('[data-source-status]')) $('#source-status').open = true;
});

function openIncomingCve(id) {
  const status = $('#cve-link-status');
  const found = data.cves.some((item) => item.id === id);
  status.hidden = found;
  status.innerHTML = found ? '' : `<strong>${escape(id)}</strong> 현재 수집 목록에 없습니다.
    ${link(`https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`, 'CVE 공식 기록')}
    ${link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, 'NVD')}`;
  showPage('cve');
  $('#query').value = id;
  selectItem(found ? id : null);
  if (found) $('#inspector h2')?.focus();
}

async function load(manual = false) {
  if (loading) return;
  loading = true;
  const reload = $('#refresh-data');
  const note = $('#refresh-note');
  reload.disabled = true;
  if (manual) note.textContent = '새 데이터를 확인하고 있습니다.';
  try {
    const response = await fetch('./data.json', {cache:'no-cache'});
    if (!response.ok) throw Error(`Snapshot HTTP ${response.status}`);
    const snapshot = await response.json();
    if (snapshot.updatedAt === data.updatedAt) {
      if (manual) note.textContent = '현재 최신 데이터를 보고 있습니다.';
      return;
    }
    const alreadyLoaded = Boolean(data.updatedAt);
    const currentSelection = selected?.id;
    const currentProduct = $('#product').value;
    data = snapshot;
    selected = data.cves.find((item) => item.id === currentSelection);
    priorities = [...data.cves].sort(comparePriority).slice(0, 3);
    const stamp = $('#freshness');
    stamp.dateTime = data.updatedAt;
    stamp.textContent = date(data.updatedAt);
    updateClock(data.updatedAt);
    $('#open-email').disabled = false;
    showSourceStatus();
    const products = [...new Set(data.cves.map((item) => item.product).filter(Boolean))].sort();
    $('#product').replaceChildren(new Option('모든 제품', ''), ...products.map((product) => new Option(product, product)));
    if (products.includes(currentProduct)) $('#product').value = currentProduct;
    renderPriority();
    renderRows();
    if (!alreadyLoaded && incomingCve) openIncomingCve(incomingCve);
    else if (page === 'home') renderOverview();
    else if (page !== 'cve') renderFeed();
    if (manual || alreadyLoaded) note.textContent = '새 데이터가 반영됐습니다.';
  } catch (error) {
    if (!data.updatedAt) $('#freshness').textContent = '수집 데이터 로딩 실패';
    if (manual) note.textContent = '갱신을 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.';
    console.error(error);
  } finally {
    reload.disabled = false;
    loading = false;
  }
}

$('#refresh-data').addEventListener('click', () => load(true));
load();
setInterval(() => {
  if (!document.hidden) load();
}, 60000);
