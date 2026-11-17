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
const labels = {home:'보안 브리핑', news:'보안 뉴스', issues:'핵심 이슈', korea:'국내 동향', cve:'CVE 목록', dark:'다크웹 보도'};
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

let data = {cves:[], news:[], sources:{}};
let selected;
let priorities = [];
let newsMode = 'recent';
let mailDraft;
let page = 'home';
let view = 'latest';
const newest = (a, b) => (Date.parse(b.published) || 0) - (Date.parse(a.published) || 0)
  || a.id.localeCompare(b.id);

function rowsForFilters() {
  const terms = $('#query').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const product = $('#product').value;
  const rows = data.cves.filter((item) => {
    const text = [item.id, item.title, item.product, ...item.fixes, item.description].join(' ').toLowerCase();
    return terms.every((term) => text.includes(term)) && (!product || item.product === product)
      && (view !== 'kev' || item.kev === true)
      && (view !== 'critical' || item.cvss >= 9)
      && (view !== 'epss' || item.epss != null);
  });
  if (view === 'epss') return rows.sort((a, b) => b.epss.score - a.epss.score || newest(a, b));
  if (view === 'kev') return rows.sort((a, b) => (b.kevDate || '').localeCompare(a.kevDate || '') || newest(a, b));
  return rows.sort(newest);
}

function renderPriority() {
  $('#priority').hidden = priorities.length === 0;
  $('#priority-list').innerHTML = priorities.map((item) => `
    <li><button type="button" class="priority-row" data-cve="${escape(item.id)}">
      <span class="priority-copy"><span>${escape(item.id)}</span><strong>${escape(item.title)}</strong></span>
      <span class="cve-meta">
        ${item.kev === true ? '<span class="pill kev">KEV</span>' : ''}
        <span class="pill">CVSS ${cvss(item)}</span>
        <span class="pill">EPSS ${epss(item)}</span>
      </span>
      <span class="priority-detail">상세 보기 <span aria-hidden="true">→</span></span>
    </button></li>`).join('');
}

// The Pages workflow starts at minute 17 on every even UTC hour.
function updateClock(stamp) {
  const collected = new Date(stamp);
  const next = new Date(collected);
  next.setUTCHours(Math.floor(next.getUTCHours() / 2) * 2, 17, 0, 0);
  if (next <= collected) next.setUTCHours(next.getUTCHours() + 2);
  $('#next-update').dateTime = next.toISOString();
  $('#next-update').textContent = date(next);
  const tick = () => {
    const seconds = Math.max(0, Math.ceil((next - Date.now()) / 1000));
    const parts = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60];
    $('#countdown').textContent = seconds
      ? parts.map((part) => String(part).padStart(2, '0')).join(':')
      : '갱신 대기';
  };
  tick();
  setInterval(tick, 1000);
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
    ['cve.now', item.url, '피드에 게시된 제목·발행일·제품 정보'],
    ['NVD', `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`, item.nvd
      ? (item.nvdStatus || '레코드 수집') : '이번 수집 범위에서 레코드 미확인'],
    ['FIRST EPSS', `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(item.id)}`,
      item.epss ? `점수 기준일 ${item.epss.date} · 향후 30일 악용 가능성 추정치` : '수집된 점수 없음'],
    ['CISA KEV', `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(item.id)}`,
      item.kevDate ? `등재일 ${item.kevDate}` : `카탈로그 상태 ${kev(item)}`],
  ];
  return sources.filter(([name]) => name !== 'cve.now' || item.origin !== 'CISA KEV').map(([name, address, note]) => `<details><summary>${icon('doc')}${name}</summary><p>${escape(note)} · ${link(address, '출처 열기')}</p></details>`).join('')
    + item.references.map((address) => `<p class="evidence-link">${link(address, 'NVD 수록 벤더 공지·패치')}</p>`).join('')
    + item.notices.map((notice) => `<p class="evidence-link">${link(notice.url, 'KISA · ' + notice.title)}</p>`).join('');
}

function renderInspector() {
  const panel = $('#inspector');
  const item = selected;
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
    <h3>영향 범위</h3>
    <dl class="facts">
      <dt>제품</dt><dd>${escape(item.product || '수집 정보 없음')}</dd>
      <dt>수정 버전 정보</dt><dd>${escape(item.fixes.join(', ') || '벤더 공지 확인 필요')}</dd>
      <dt>CVSS 제공처</dt><dd>${escape(item.cvssSource || '미확인')}</dd>
      <dt>공개 시각</dt><dd>${escape(date(item.published))}</dd>
    </dl>
    <h3>취약점 설명</h3>
    <p class="cve-summary">${escape(item.description || '수집된 NVD 설명이 없습니다.')}</p>
    <h3>출처 확인</h3>
    <div id="source-list">${evidence(item)}</div>
    <div class="actions">
      <button class="accent" data-guide="analysis">${icon('search')}CVE 상세</button>
      <button class="outline" data-guide="check">${icon('shield')}안전한 점검</button>
    </div>`;
}

function showPage(name) {
  page = name;
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
}

function renderOverview() {
  const sections = [
    ['issues', '핵심 이슈', data.news.filter((article) => article.kind === 'advisory' || article.cves.length)],
    ['news', '최신 뉴스', data.news.filter((article) => article.kind !== 'advisory')],
    ['korea', '보호나라 공지', data.news.filter((article) => article.kind === 'advisory')],
    ['dark', '다크웹 보도', data.news.filter((article) => article.dark)],
  ];
  const view = $('#overview');
  view.innerHTML = sections.map(([target, title, articles]) => `
    <section class="digest">
      <header><h3>${title}</h3><button data-open="${target}">전체 보기 <span aria-hidden="true">→</span></button></header>
      ${articles.slice(0, 4).map((article) => `
        <article><small>${escape(article.publisher)} · ${escape(date(article.date))}</small>
        <h4>${link(article.url, article.title)}</h4></article>`).join('') || '<p>수집된 항목 없음</p>'}
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
  const article = (item) => `<article>
    <small>${escape(item.publisher)} · ${escape(date(item.date))}${item.kind === 'aggregated' ? ' · Google 뉴스 경유' : ''}</small>
    <h3>${link(item.url, item.title)}</h3></article>`;
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
      `<section class="news-topic"><h3>${escape(name)} <span>${entries.length}건</span></h3>${entries.map(article).join('')}</section>`).join('')
      : items.map(article).join('')) || '<p>조건에 맞는 기사가 없습니다.</p>';
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
  const analysis = mode === 'analysis';
  $('#guide-content').innerHTML = `
    <span class="eyebrow">${escape(item.id)}</span>
    <h2 id="guide-title">${analysis ? 'CVE 상세' : '안전한 점검'}</h2>
    <p>${escape(item.title)}</p>
    ${analysis ? `<h3>NVD 설명</h3><p>${escape(item.description || '이번 수집에서 확보한 NVD 설명이 없습니다.')}</p>
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
$('#filters').addEventListener('input', renderRows);
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
$('#inspector').addEventListener('click', (event) => {
  const button = event.target.closest('[data-guide]');
  if (button) showGuide(selected, button.dataset.guide);
});
function openCve(id) {
  $('#filters').reset();
  view = 'latest';
  showPage('cve');
  selectItem(id);
  $('#inspector h2')?.focus();
}

$('#overview').addEventListener('click', (event) => {
  const section = event.target.closest('[data-open]');
  if (section) showPage(section.dataset.open);
  const item = event.target.closest('[data-cve]');
  if (item) openCve(item.dataset.cve);
});
$('#priority-list').addEventListener('click', (event) => {
  const item = event.target.closest('[data-cve]');
  if (item) openCve(item.dataset.cve);
});

function buildMail() {
  const sections = [];
  const cves = page === 'home' ? priorities : page === 'cve' ? (selected ? [selected] : rowsForFilters()) : [];
  if (cves.length) sections.push(['우선 확인할 CVE', cves.map((item) => ({
    title: `${item.id} · ${item.title}`,
    meta: `CVSS ${cvss(item)} · EPSS ${epss(item)} · KEV ${kev(item)}`,
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.id)}`,
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

async function load() {
  try {
    const response = await fetch('./data.json', {cache:'no-cache'});
    if (!response.ok) throw Error(`Snapshot HTTP ${response.status}`);
    data = await response.json();
    priorities = [...data.cves].sort(comparePriority).slice(0, 3);
    const stamp = $('#freshness');
    stamp.dateTime = data.updatedAt;
    stamp.textContent = date(data.updatedAt);
    updateClock(data.updatedAt);
    $('#open-email').disabled = false;
    const states = {ok:'수집', stale:'이전 데이터', unavailable:'수집 실패'};
    $('#source-status-list').innerHTML = Object.entries(data.sources).map(([name, status]) =>
      `<li>${escape(name)} <span>${states[status.state]} · ${status.count}건${status.at ? ` · ${escape(date(status.at))}` : ''}</span></li>`).join('');
    const products = [...new Set(data.cves.map((item) => item.product).filter(Boolean))].sort();
    products.forEach((product) => $('#product').add(new Option(product, product)));
    renderPriority();
    renderRows();
    if (page === 'home') renderOverview();
    else if (page !== 'cve') renderFeed();
  } catch (error) {
    $('#freshness').textContent = '데이터를 불러오지 못했습니다. 새로고침해 주세요.';
    console.error(error);
    renderRows();
  }
}

load();
