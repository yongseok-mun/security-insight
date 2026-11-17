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

// Keep the existing snapshot order for completion records saved by earlier releases.
const remediationFields = ['패치 버전', '해결책', '완화책', 'CISA 조치 권고'];

function remediationValues(item) {
  return [
    [...new Set([...(item.fixes || []), ...(item.describedFixes || [])])].sort(),
    [...new Set(item.cna?.solutions || [])].sort(),
    [...new Set(item.cna?.workarounds || [])].sort(),
    item.requiredAction || '',
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
  return review.fingerprint !== remediationFingerprint(item) || remediationSinceReview(item, review).length
    ? 'recheck' : 'done';
}

function completedRemediation(review) {
  try {
    const snapshot = JSON.parse(review.fingerprint);
    if (Array.isArray(snapshot) && snapshot.length === remediationFields.length
      && snapshot.slice(0, 3).every((values) => Array.isArray(values)
        && values.every((value) => typeof value === 'string'))
      && typeof snapshot[3] === 'string') return snapshot;
  } catch { /* Some stored reviews may be missing a readable snapshot. */ }
  return null;
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

function installedVersionOutcome(product, version, build, conditions) {
  const upstream = build === 'upstream';
  const result = upstream ? evaluateInstalledVersion(product, version) : null;
  let status = 'unknown';
  let headline = '추가 확인 필요';
  let explanation = '벤더 공지에서 제품 에디션·기능 설정과 영향 조건을 확인하세요.';
  if (!upstream) {
    explanation = '배포판·백포트·자체 빌드는 설치 패키지 릴리스와 해당 공급사의 보안 공지로 확인하세요.';
    if (!build) explanation = '설치 유형을 선택하면 공지 범위와 대조할 수 있습니다.';
  } else if (result.status === 'unaffected') {
    status = 'unaffected';
    headline = '공지상 해당 버전은 영향 없음';
    explanation = '선택한 제품·플랫폼의 공지 범위를 기준으로 확인했습니다.';
  } else if (result.status === 'affected' && conditions === 'met') {
    status = 'affected';
    headline = '공지상 영향 조건에 해당';
    explanation = '확인한 조건과 설치 버전을 기준으로 패치 또는 완화조치를 검토하세요.';
  } else if (result.status === 'affected' && conditions === 'not-met') {
    explanation = '버전은 영향 범위에 해당합니다. 확인한 필수 조건과 다른 악용 경로가 있는지 공지에서 다시 대조하세요.';
  }
  return {status, headline, explanation, result};
}

const batchLabels = {affected:'영향 범위 해당', unaffected:'공지상 영향 없음', unknown:'추가 확인 필요'};
const cnaRecordUrl = (item) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(item.id)}`;
const nvdRecordUrl = (item) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`;

function csvCell(value) {
  const text = String(value ?? '');
  const safe = /^[\s\uFEFF]*[=+@-]|^[\t\r\n]/.test(text) ? "'" + text : text;
  return '"' + safe.replace(/"/g, '""') + '"';
}

function downloadBatchCsv(button, item) {
  const form = button.closest('[data-version-check]');
  const product = item?.cna?.affected?.[Number(form.elements.product.value)];
  const rows = [...form.querySelectorAll('[data-version-status]:not([hidden])')];
  if (!product || !rows.length) return;
  const vendors = (item.cna?.references || []).map(publicUrl).filter(Boolean);
  const header = ['CVE', '제품', '설치 버전', '판정', '판정 근거', 'CNA 출처', '벤더 출처'];
  const body = rows.map((row) => [
    item.id, compareProductLabel(product, item.product), ...[...row.cells].map((cell) => cell.textContent.trim()),
    cnaRecordUrl(item), vendors.join(' '),
  ]);
  const csv = '\uFEFF' + [header, ...body].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
  downloadBlob(new Blob([csv], {type:'text/csv;charset=utf-8'}), `${item.id}-version-check.csv`);
}

function showInstalledVersionResult(event, item) {
  const form = event.target.closest('[data-version-check]');
  if (!form) return;
  event.preventDefault();
  const fields = form.elements;
  const product = item?.cna?.affected?.[Number(fields.product.value)];
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
  const fixes = [...new Set([...(item.fixes || []), ...(item.describedFixes || [])])];
  const fixNote = fixes.join(', ') || '확인된 수정 버전 없음 · 원문 공지 참조';
  if (batch) {
    const counts = Object.entries(batchLabels).map(([status, label]) =>
      `${label} ${results.filter((entry) => entry.status === status).length}건`).join(' · ');
    output.dataset.summary = [counts, ...results.map(({version, status}) => `${version} · ${batchLabels[status]}`),
      `수정 정보 · ${fixNote}`].join('\n');
    output.innerHTML = `<p>${escape(counts)}</p>
      <label>결과 필터 <select data-batch-filter>
        <option value="">전체</option><option value="review">영향 범위 해당 + 추가 확인 필요</option>
        ${Object.entries(batchLabels).map(([status, label]) => `<option value="${status}">${label}</option>`).join('')}
      </select></label>
      <button type="button" class="outline" data-export-batch>현재 결과 CSV 다운로드</button>
      <div class="batch-results"><table><thead><tr><th scope="col">설치 버전</th><th scope="col">대조 결과</th><th scope="col">판단 근거</th></tr></thead>
      <tbody>${results.map(({version, status, result, explanation}) => `<tr data-version-status="${status}">
        <th scope="row">${escape(version)}</th><td>${batchLabels[status]}</td>
        <td>${escape(result?.reason || explanation)}</td></tr>`).join('')}</tbody></table></div>
      <p data-batch-empty hidden>이 조건에 해당하는 버전이 없습니다.</p>
      <p>수정 정보 · ${escape(fixNote)}</p>`;
    return;
  }
  const [{version, headline, explanation, result}] = results;
  output.dataset.summary = [`입력 버전: ${version}`, headline, explanation, result && `버전 근거 · ${result.reason}`,
    conditionNotes.length && `제품·CVSS 참고 조건 · ${conditionNotes.join(' / ')}`, `수정 정보 · ${fixNote}`].filter(Boolean).join('\n');
  output.innerHTML = `
    <strong>${headline}</strong><p>${explanation}</p>
    ${result ? `<p>버전 근거 · ${escape(result.reason)}</p>` : ''}
    ${result?.status === 'unknown' && product.versions?.length ? `<details>
      <summary>CNA 버전 범위 직접 대조</summary>
      <ul class="detail-list">${product.versions.map((entry) => `<li>${escape(versionLabel(entry))}</li>`).join('')}</ul>
    </details>` : ''}
    ${conditionNotes.length ? `<p>제품·CVSS 참고 조건 · ${escape(conditionNotes.join(' / '))}</p>` : ''}
    <p>수정 정보 · ${escape(fixNote)}</p>`;
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

function remediationComparison(item, review) {
  const completed = completedRemediation(review);
  const current = remediationValues(item);
  const events = remediationSinceReview(item, review)
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  const rows = completed ? remediationFields.flatMap((field, index) => {
    if (JSON.stringify(completed[index]) === JSON.stringify(current[index])) return [];
    const latest = events.find((event) => event.changes?.some((change) => change.field === field));
    const values = (value) => (Array.isArray(value) ? value : [value]).filter(Boolean);
    return [{field, before:values(completed[index]), after:values(current[index]), at:latest?.at}];
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
    field === remediationFields[0] ? [] : [...before, ...after]);
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
  const vendors = [...new Set((item.cna?.references || []).map(publicUrl).filter(Boolean))]
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
    ${item.fixes?.length ? `<p>cve.now 수정 정보 · ${escape(item.fixes.join(', '))} ${link(item.url, 'cve.now')}</p>` : ''}
    ${item.describedFixes?.length ? `<p>수집 설명에서 추출 · ${escape(item.describedFixes.join(', '))} ${descriptionLink}</p>` : ''}
    ${!item.fixes?.length && !item.describedFixes?.length ? `<p>구조화된 패치 버전 미확인 · ${cna}</p>` : ''}
    <h3>해결책·완화조치</h3>
    ${[...solutions.map((source) => pair('CNA 해결책',source,koreanText(source,translations),cna)),
      ...workarounds.map((source) => pair('CNA 완화책',source,koreanText(source,translations),cna)),
      pair('CISA KEV 권고',requiredAction,koreanText(requiredAction,translations),
        link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`, 'CISA KEV 원문'))].join('')}
    ${vendors ? `<p>벤더 공지 · ${vendors}</p>` : ''}`;
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
  const [fixes, solutions, workarounds, requiredAction] = remediationValues(item);
  const cna = cnaRecordUrl(item);
  const nvd = nvdRecordUrl(item);
  const vendors = [...new Set((item.cna?.references || []).map(publicUrl).filter(Boolean))];
  const descriptionRefs = item.descriptionEnSource === 'CNA' ? [`- 설명에 명시된 수정 버전 근거(CNA): ${cna}`]
    : item.descriptionEnSource === 'NVD' ? [`- 설명에 명시된 수정 버전 근거(NVD): ${nvd}`]
      : [`- 설명에 명시된 수정 버전 확인(NVD): ${nvd}`, `- CNA 레코드: ${cna}`];
  const changes = [];
  if (comparison) {
    const {completed, events, rows} = comparison;
    changes.push('', '[조치 완료 이후 변경]');
    if (!completed) changes.push('완료 당시 비교 정보를 확인할 수 없습니다.');
    if (!rows.length && events.length) changes.push('수집된 변경 이력 기준입니다.');
    for (const {field, before, after, at} of advisoryChanges(comparison)) {
      const value = (entries) => entries.map((entry) => field === remediationFields[0] ? entry
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
    `- 패치: ${fixes.length ? `수집된 수정 버전 ${fixes.join(', ')}. 대상 릴리스의 수정 버전을 벤더 공지에서 확인 후 적용합니다.`
      : '대상 릴리스의 수정 버전과 적용 절차를 벤더 공지에서 확인합니다.'}`,
    ...(item.fixes?.length && publicUrl(item.url) ? [`- 패치 버전 참고(cve.now): ${publicUrl(item.url)}`] : []),
    ...(item.describedFixes?.length ? descriptionRefs : []),
    ...[...new Set(solutions.map(localizedAction))].map((solution) => `  CNA 해결책: ${solution}`),
    ...(workarounds.length ? [...new Set(workarounds.map(localizedAction))].map((workaround) => `- 임시 완화(CNA): ${workaround}`)
      : ['- 임시 완화: 수집된 CNA 권고가 없습니다. 즉시 패치가 어려우면 벤더가 안내한 우회책의 적용 가능 여부를 확인합니다.']),
    ...(solutions.length || workarounds.length ? [`- 해결책·완화조치 근거(CNA): ${cna}`] : []),
    ...(requiredAction ? [`- CISA KEV 조치 권고: ${localizedAction(requiredAction)}`] : []),
    '- 보안장비 정책(보완 통제): 영향 트래픽이 장비를 통과하고 해당 CVE의 벤더 검증 규칙이 있는 경우, 정상 업무 트래픽의 오탐을 확인한 뒤 WAF·IPS 정책 적용을 검토합니다.',
    networkPath ? '- 접근제어: 영향 인터페이스에 불필요한 접근을 차단하고 필요한 출발지·네트워크만 허용합니다.'
      : '- 접근제어: 영향 기능을 이용할 수 있는 계정·서비스 권한을 확인하고 불필요한 권한을 줄입니다.',
    '- 조치 후 설치 버전·설정과 정상 서비스 동작을 재확인합니다. 보안장비 정책을 적용했다면 로그에서 탐지·차단과 오탐 여부를 확인합니다.',
    ...changes,
    '',
    '[근거 링크]',
    ...vendors.map((url) => `- 벤더 공지: ${url}`),
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
const advisoryStorageKey = (item) => `security-insight.advisory-draft.v1.${item.id}`;
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

function showAdvisoryDraftChanges() {
  const {item, baseline} = advisoryDraft;
  const area = advisoryDialog.querySelector('[data-advisory-draft-changes]');
  const {rows, events} = remediationComparison(item, baseline);
  area.hidden = !rows.length && !events.length;
  const currentValues = rows.length ? changeDetails({changes:rows})
    : events.slice(0, 3).map((event) => changeDetails(event)).join('');
  area.querySelector('[data-advisory-change-values]').innerHTML = currentValues;
}

function saveAdvisoryDraft(acknowledge = false) {
  if (!advisoryDraft) return;
  const {item, generated, comparison, version} = advisoryDraft;
  const baseline = acknowledge ? {reviewedThrough:advisoryDraft.asOf, fingerprint:remediationFingerprint(item)} : advisoryDraft.baseline;
  const saved = {
    body:advisoryDialog.querySelector('textarea').value, generated, baseline, savedAt:new Date().toISOString(),
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
  } catch {
    draftStatus().textContent = '이 브라우저에 초안을 저장하지 못했습니다. 공지문 복사나 HTML 다운로드를 이용하세요.';
  }
}

function openAdvisory(button, item) {
  const panel = button.closest('.inspector');
  const result = panel.querySelector('.version-result');
  const fields = result?.closest('form').elements;
  const summary = result && !result.hidden ? result.dataset.summary : '';
  const saved = loadAdvisoryDraft(item);
  advisoryDraft = {
    item,
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
  advisoryDialog.querySelector('[data-advisory-evidence]').innerHTML = advisoryEvidence(item, advisoryDraft.translations);
  advisoryDialog.querySelector('[data-copy-fallback]').hidden = true;
  for (const key of ['comparison', 'version']) {
    const option = advisoryDialog.querySelector(`[name="${key}"]`);
    option.checked = Boolean(saved?.[key]);
    option.closest('label').hidden = !advisoryDraft[key];
  }
  const translate = advisoryDialog.querySelector('[data-translate-advisory]');
  translate.hidden = !('Translator' in globalThis) || advisoryTranslationSources(item, advisoryDraft.comparison)
    .every((source) => advisoryDraft.translations.has(source));
  translate.disabled = false;
  advisoryDialog.querySelector('[data-translation-status]').textContent = '';
  draftStatus().textContent = saved ? `저장한 초안을 불러왔습니다${Number.isFinite(Date.parse(saved.savedAt)) ? ` · ${date(saved.savedAt)}` : ''}.` : '';
  advisoryDialog.querySelector('[data-remove-advisory]').hidden = !saved;
  if (!saved) updateAdvisory();
  else advisoryDialog.querySelector('[data-copy-status]').textContent = '';
  showAdvisoryDraftChanges();
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
advisoryDialog.querySelector('[data-save-advisory]').addEventListener('click', () => saveAdvisoryDraft());
advisoryDialog.querySelector('[data-remove-advisory]').addEventListener('click', (event) => {
  if (!advisoryDraft) return;
  try {
    localStorage.removeItem(advisoryStorageKey(advisoryDraft.item));
    event.currentTarget.hidden = true;
    draftStatus().textContent = '저장본을 삭제했습니다. 열린 문안은 계속 편집할 수 있습니다.';
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
for (const panel of [$('#inspector'), $('#priority-inspector')]) {
  panel.addEventListener('submit', (event) => showInstalledVersionResult(event,
    panel.id === 'inspector' ? selected : priorities.find((item) => item.id === prioritySelection)));
  panel.addEventListener('input', (event) => {
    const form = event.target.closest('[data-version-check]');
    if (!form || event.target.matches('[data-batch-filter]')) return;
    form.querySelector('.version-result').hidden = true;
    if (event.target === form.elements.batch) {
      const batch = event.target.checked;
      for (const [field, active] of [[form.elements.version, !batch], [form.elements.versions, batch]]) {
        field.required = active;
        field.disabled = !active;
        field.closest('label').hidden = !active;
      }
    }
  });
  panel.addEventListener('change', (event) => {
    if (!event.target.matches('[data-batch-filter]')) return;
    const output = event.target.closest('.version-result');
    const filter = event.target.value;
    let visible = 0;
    for (const row of output.querySelectorAll('[data-version-status]')) {
      const status = row.dataset.versionStatus;
      row.hidden = Boolean(filter) && (filter === 'review' ? status === 'unaffected' : filter !== status);
      if (!row.hidden) visible++;
    }
    output.querySelector('[data-batch-empty]').hidden = visible > 0;
    output.querySelector('[data-export-batch]').disabled = visible === 0;
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
  downloadBlob(new Blob([message], {type:'message/rfc822'}), 'security-insight.eml');
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
