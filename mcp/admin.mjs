export function adminPage(nonce) {
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Insight · MCP 키 관리</title>
<style nonce="${nonce}">
  :root { color-scheme: dark; font: 16px system-ui, sans-serif; background: #0d1420; color: #eef4ff; }
  body { max-width: 60rem; margin: 0 auto; padding: clamp(1rem, 5vw, 3rem); }
  h1 { margin: .3rem 0 1.25rem; font-size: clamp(1.5rem, 4vw, 2.1rem); }
  p { color: #b5c5dd; }
  section { border: 1px solid #354660; border-radius: .8rem; background: #152133; padding: 1.25rem; margin: 1rem 0; }
  h2 { font-size: 1.1rem; margin: 0 0 .8rem; }
  label, output { display: block; margin-bottom: .5rem; }
  input, button { font: inherit; min-height: 2.6rem; border-radius: .4rem; box-sizing: border-box; }
  input { background: #0d1420; border: 1px solid #526584; color: inherit; width: min(100%, 31rem); padding: .55rem; }
  button { background: #b9d6ff; color: #0d1420; border: 0; padding: .45rem .8rem; cursor: pointer; }
  button.secondary { background: #293c58; color: #eef4ff; }
  button:focus-visible, input:focus-visible { outline: 2px solid #90dcff; outline-offset: 3px; }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
  #keys { list-style: none; margin: 0; padding: 0; }
  li { display: flex; justify-content: space-between; flex-wrap: wrap; gap: .5rem; border-top: 1px solid #354660; padding: .75rem 0; }
  li small { display: block; color: #b5c5dd; overflow-wrap: anywhere; }
  code { overflow-wrap: anywhere; }
</style>
</head>
<body>
<h1>Security Insight MCP 키 관리</h1>
<section aria-labelledby="login-title">
  <h2 id="login-title">관리자 인증</h2>
  <form id="login">
    <label for="token">관리자 토큰</label>
    <div class="row"><input id="token" type="password" required autocomplete="off">
      <button>인증</button><button id="logout" class="secondary" type="button" hidden>잠금</button></div>
  </form>
</section>
<section id="management" aria-labelledby="keys-title" hidden>
  <h2 id="keys-title">발급된 MCP 키</h2>
  <p>MCP 주소 <code id="endpoint"></code></p>
  <form id="create">
    <label for="label">키 이름</label>
    <div class="row"><input id="label" maxlength="80" required placeholder="예: 분석팀 데스크톱">
      <button>키 발급</button></div>
  </form>
  <ul id="keys"></ul>
  <div id="secret" hidden>
    <label for="value">키 원문</label>
    <div class="row"><input id="value" readonly autocomplete="off">
      <button id="copy" type="button">복사</button><button id="hide" class="secondary" type="button">숨기기</button></div>
  </div>
</section>
<output id="status" role="status"></output>
<script nonce="${nonce}">
const byId = (id) => document.getElementById(id);
let token = '';
let generation = 0;
let busy = false;
let hideTimer;
const status = (message) => { byId('status').textContent = message; };
byId('endpoint').textContent = location.origin + '/mcp';

function hideKey() {
  clearTimeout(hideTimer);
  byId('value').value = '';
  byId('secret').hidden = true;
}
function showKey(key) {
  hideKey();
  byId('value').value = key;
  byId('secret').hidden = false;
  hideTimer = setTimeout(hideKey, 30000);
}
function lock() {
  generation++;
  token = '';
  byId('token').value = '';
  byId('management').hidden = true;
  byId('logout').hidden = true;
  byId('keys').replaceChildren();
  hideKey();
}
async function api(path = '', method = 'GET', body) {
  const current = generation;
  const response = await fetch('/admin/keys' + path, {
    method, cache: 'no-store', credentials: 'omit',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (current !== generation) throw new Error('');
  if (response.status === 401) lock();
  if (!response.ok) throw new Error(data.error || '요청에 실패했습니다.');
  return data;
}
async function action(run) {
  if (busy) return;
  busy = true;
  status('');
  try { await run(); } catch (error) { status(error.message); }
  finally { busy = false; }
}
function button(text, run) {
  const element = document.createElement('button');
  element.type = 'button';
  element.className = 'secondary';
  element.textContent = text;
  element.onclick = () => action(run);
  return element;
}
async function refresh() {
  const { keys } = await api();
  byId('keys').replaceChildren(...keys.map((key) => {
    const row = document.createElement('li');
    const info = document.createElement('div');
    info.textContent = key.label;
    const details = document.createElement('small');
    const date = new Date(key.createdAt).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
    details.textContent = key.prefix + '… · ' + date + ' KST · ' + (key.revokedAt ? '폐기됨' : '활성');
    info.append(details);
    row.append(info);
    if (!key.revokedAt) {
      const controls = document.createElement('div');
      controls.className = 'row';
      controls.append(button('키 보기', async () => {
        showKey((await api('/' + key.id + '/reveal', 'POST')).key);
      }), button('폐기', async () => {
        if (!confirm('이 키를 폐기하면 연결된 MCP 클라이언트에서 즉시 사용할 수 없게 됩니다. 폐기할까요?')) return;
        await api('/' + key.id, 'DELETE');
        hideKey();
        await refresh();
        status('키를 폐기했습니다.');
      }));
      row.append(controls);
    }
    return row;
  }));
  if (!keys.length) {
    const empty = document.createElement('li');
    empty.textContent = '발급된 키가 없습니다.';
    byId('keys').append(empty);
  }
}
byId('login').onsubmit = (event) => {
  event.preventDefault();
  action(async () => {
    lockForLogin();
    await refresh();
    byId('management').hidden = false;
    byId('logout').hidden = false;
    status('관리자 인증이 완료됐습니다.');
  });
};
function lockForLogin() {
  const input = byId('token').value.trim();
  lock();
  token = input;
}
byId('logout').onclick = () => { lock(); status('관리 화면을 잠갔습니다.'); };
byId('create').onsubmit = (event) => {
  event.preventDefault();
  action(async () => {
    const result = await api('', 'POST', { label: byId('label').value });
    byId('label').value = '';
    showKey(result.key);
    await refresh();
    status('키를 발급했습니다.');
  });
};
byId('hide').onclick = hideKey;
byId('copy').onclick = () => action(async () => {
  await navigator.clipboard.writeText(byId('value').value);
  status('키를 복사했습니다.');
});
window.addEventListener('pagehide', lock);
</script>
</body>
</html>`;
}
