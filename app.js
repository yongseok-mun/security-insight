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
document.querySelectorAll('.priority li').forEach((node) => {
  node.insertAdjacentHTML('afterbegin', icon('check'));
});

const vulnerabilities = [
  ['게이트웨이 인증 우회',9.8,82,true,'게이트웨이','Example Networks','3.4.2','인증 우회','관리 인터페이스에 접근해 설정을 변경하거나 정보를 조회할 수 있습니다.'],
  ['웹 관리자 페이지 명령 실행',9.6,76,true,'웹 관리자','Example Web','2.8.0','명령 실행','관리 서비스 권한으로 명령이 실행될 수 있습니다.'],
  ['원격 코드 실행 (RCE)',9.6,71,false,'API 서버','Example Web','1.9.0','원격 코드 실행','API 프로세스 권한으로 코드가 실행될 수 있습니다.'],
  ['권한 상승',9.1,58,true,'접근 관리','Example Identity','5.2.1','권한 상승','기존 계정에 관리자 권한이 부여될 수 있습니다.'],
  ['경로 탐색을 통한 파일 접근',9.0,55,false,'파일 서버','Example Files','4.1.0','경로 탐색','서비스에서 읽을 수 있는 파일이 노출될 수 있습니다.'],
  ['관리자 기능 인증 우회',8.8,49,false,'웹 관리자','Example Web','2.8.0','인증 우회','관리자 전용 기능이 노출될 수 있습니다.'],
  ['서비스 거부 (DoS)',7.5,35,false,'게이트웨이','Example Networks','3.4.2','서비스 거부','게이트웨이 요청 처리가 중단될 수 있습니다.'],
  ['민감 정보 노출',7.5,28,false,'파일 서버','Example Files','4.1.0','정보 노출','운영 설정이 조회될 수 있습니다.'],
  ['크로스 사이트 스크립팅 (XSS)',6.5,18,false,'웹 관리자','Example Web','2.8.0','XSS','사용자 브라우저에서 스크립트가 실행될 수 있습니다.'],
  ['설정 오류에 의한 정보 노출',6.3,12,false,'접근 관리','Example Identity','5.2.1','정보 노출','진단 정보가 노출될 수 있습니다.'],
].map(([title, cvss, epss, kev, product, vendor, version, type, impact], index) => ({
  id: `예시 CVE ${String.fromCharCode(65 + index)}`, title, cvss, epss, kev, product, vendor, version, type, impact,
}));

const sources = [
  {name:'벤더 공지', icon:'doc', detail:'제품별 영향 버전, 수정 빌드 및 완화책의 근거입니다. 이 예시에 연결된 실제 벤더 공지는 없습니다.'},
  {name:'NVD', icon:'news', detail:'CVSS 버전과 벡터를 확인합니다. 표시된 점수는 시안 데이터입니다.', url:'https://nvd.nist.gov/vuln/search'},
  {name:'FIRST EPSS', icon:'link', detail:'EPSS는 향후 30일 내 악용 가능성 추정치입니다. 이 예시에서 표시한 수치는 시안 데이터입니다.', url:'https://www.first.org/epss/'},
  {name:'CISA KEV', icon:'shield', detail:'카탈로그 등록 상태를 확인합니다. 미등재 상태만으로 실제 악용 여부를 판단할 수 없습니다.', url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'},
];

const feeds = {
  news: {title:'실시간 뉴스', items:[['벤더 공지 예시','게이트웨이 보안 업데이트 배포','시안 기사 · 수집 연동 전']]},
  issues: {title:'핵심 이슈', items:[['우선 점검 예시','외부에 노출된 관리 인터페이스 우선 확인','예시 CVE A 관련 점검']]},
  korea: {title:'국내 동향', items:[['국내 공지 예시','네트워크 장비 보안 공지 모니터링','실제 기관 공지와 연결되면 원문을 표시합니다.']]},
  dark: {title:'다크웹', items:[['미확인 제보 예시','게이트웨이 공격 도구 거래 주장','원출처와 독립적인 근거가 확인될 때까지 미확인으로 표시합니다.']]},
};

const filters = ['product', 'vendor', 'version'];
const filterLabels = {product:'제품', vendor:'벤더', version:'버전'};
const priority = vulnerabilities[0];
let selected = priority;
let sort = {key:'cvss', direction:-1};

for (const key of filters) {
  const select = $(`#${key}`);
  select.add(new Option(`모든 ${filterLabels[key]}`, ''));
  const values = [...new Set(vulnerabilities.map((item) => item[key]))].sort();
  values.forEach((value) => select.add(new Option(value, value)));
}

function filteredRecords() {
  const query = $('#query').value.trim().toLowerCase();
  return vulnerabilities.filter((item) => {
    const text = Object.values(item).join(' ').toLowerCase();
    return text.includes(query) && (!$('#kev').checked || item.kev)
      && filters.every((key) => !$(`#${key}`).value || item[key] === $(`#${key}`).value);
  }).sort((a, b) => (a[sort.key] - b[sort.key]) * sort.direction);
}

function kevPill(item) {
  return `<span class="pill ${item.kev ? 'critical' : ''}">${item.kev ? '등재' : '미등재'}</span>`;
}

function renderRows(records) {
  const rows = $('#rows');
  rows.innerHTML = records.map((item) => {
    const active = item === selected;
    const severity = item.cvss >= 9 ? 'critical' : item.cvss >= 7 ? 'high' : '';
    return `<tr class="${active ? 'selected' : ''}">
      <td><button type="button" aria-pressed="${active}" data-id="${item.id}"><strong>${item.id}</strong><small>${item.title}</small></button></td>
      <td><span class="pill ${severity}">${item.cvss.toFixed(1)}</span></td><td>${item.epss}%</td><td>${kevPill(item)}</td>
    </tr>`;
  }).join('') || '<tr><td class="empty" colspan="4">조건에 맞는 CVE가 없습니다.</td></tr>';
  $('#count').textContent = `총 ${records.length}건 (시안 데이터)`;
}

function renderInspector(item) {
  const panel = $('#inspector');
  if (!item) {
    panel.innerHTML = '<p class="empty">검색 조건을 바꾸면 상세 정보를 확인할 수 있습니다.</p>';
    return;
  }
  panel.innerHTML = `
    <div class="eyebrow"><span>${item.id}</span>${item.kev ? '<span class="pill critical">KEV 등재</span>' : ''}</div>
    <h2 tabindex="-1">${item.title}</h2>
    <div class="metrics">
      <div>CVSS v3.1<strong>${item.cvss.toFixed(1)}</strong></div>
      <div>EPSS<strong>${item.epss}%</strong></div>
      <div>KEV<strong>${item.kev ? '등재' : '미등재'}</strong></div>
    </div>
    <h3>영향 범위</h3>
    <dl class="facts">
      <dt>영향 제품</dt><dd>${item.vendor} ${item.product}</dd>
      <dt>영향 버전</dt><dd>≤ ${item.version} (예시)</dd>
      <dt>취약점 유형</dt><dd>${item.type}</dd>
      <dt>주요 영향</dt><dd>${item.impact}</dd>
    </dl>
    <h3>출처 검증</h3>
    <div id="source-list">${sources.map((source) => `
      <details><summary>${icon(source.icon)}${source.name}<small>시안 · 검증 전</small></summary>
        <p>${source.detail} ${source.url ? `<a href="${source.url}" target="_blank" rel="noopener noreferrer">공식 사이트</a>` : ''}</p>
      </details>`).join('')}</div>
    <div class="actions">
      <button class="accent" data-guide="analysis">${icon('search')}심층 분석 보기</button>
      <button class="outline" data-guide="check">${icon('shield')}안전한 점검</button>
    </div>`;
}

function render() {
  const records = filteredRecords();
  if (!records.includes(selected)) selected = records[0] || null;
  renderRows(records);
  renderInspector(selected);
  document.querySelectorAll('[data-sort]').forEach((button) => {
    const active = button.dataset.sort === sort.key;
    button.querySelector('span').textContent = active && sort.direction === 1 ? '▴' : '▾';
    button.closest('th').setAttribute('aria-sort', active ? (sort.direction === 1 ? 'ascending' : 'descending') : 'none');
  });
}

function showPage(page) {
  const cve = page === 'cve';
  $('#cve-view').hidden = !cve;
  $('#feed').hidden = cve;
  $('#page-title').textContent = cve ? 'CVE 우선순위' : feeds[page].title;
  document.querySelectorAll('[data-page]').forEach((button) => {
    if (button.dataset.page === page) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  if (!cve) $('#feed').innerHTML = feeds[page].items.map(([label, title, copy]) =>
    `<article><small>${label}</small><h3>${title}</h3><p>${copy}</p></article>`
  ).join('');
}

function showGuide(item, mode) {
  const analysis = mode === 'analysis';
  $('#guide-content').innerHTML = `
    <small class="demo">시안 데이터</small>
    <h2 id="guide-title">${analysis ? 'CVE 심층 분석' : '안전한 점검'}</h2>
    <p>${item.id} · ${item.title}</p>
    ${analysis ? `<h3>공격 조건과 영향</h3><p>${item.vendor} ${item.product}의 영향을 받는 버전과 관련 기능의 활성화 여부를 확인합니다. ${item.impact}</p>` : ''}
    <h3>읽기 전용 점검 순서</h3>
    <ol>
      <li>자산 목록에서 ${item.product}의 소유자와 인터넷 노출 여부를 확인합니다.</li>
      <li>관리 콘솔의 시스템 정보 화면 또는 승인된 자산 수집 기록에서 제품 버전과 빌드를 조회합니다.</li>
      <li>조회한 값을 벤더 공지의 영향 범위 및 수정 릴리스와 대조합니다. ${item.version}은 시안의 예시 버전입니다.</li>
    </ol>
    ${analysis ? '<h3>대응 및 확인</h3><p>벤더 지침을 적용한 후 버전·빌드와 관리 인터페이스 노출 상태를 다시 확인합니다.</p>' : ''}`;
  $('#guide').showModal();
}

$('#filters').addEventListener('submit', (event) => event.preventDefault());
$('#filters').addEventListener('input', render);
$('#rows').addEventListener('click', (event) => {
  const button = event.target.closest('[data-id]');
  if (!button) return;
  selected = vulnerabilities.find((item) => item.id === button.dataset.id);
  render();
  if (matchMedia('(max-width:730px)').matches) {
    $('#inspector').scrollIntoView({block:'start'});
    $('#inspector h2').focus({preventScroll:true});
  } else {
    [...document.querySelectorAll('[data-id]')].find((control) => control.dataset.id === selected.id).focus();
  }
});
document.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => {
  const key = button.dataset.sort;
  sort = {key, direction:sort.key === key ? -sort.direction : -1};
  render();
}));
document.querySelectorAll('[data-page]').forEach((button) => button.addEventListener('click', () => showPage(button.dataset.page)));
$('#inspector').addEventListener('click', (event) => {
  const button = event.target.closest('[data-guide]');
  if (button && selected) showGuide(selected, button.dataset.guide);
});
$('#top-check').addEventListener('click', () => showGuide(priority, 'check'));
$('#top-source').addEventListener('click', () => {
  showPage('cve');
  $('#filters').reset();
  selected = priority;
  render();
  const disclosure = $('#source-list details');
  disclosure.open = true;
  disclosure.querySelector('summary').focus();
});

render();
