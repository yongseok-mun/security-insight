# Security Insight 원격 MCP

GitHub Pages의 공개 게시본을 조회하는 별도 Cloudflare Worker입니다. 브라우저에 저장된 관심 제품, 자산 CSV와 Gmail 정보는 서버에 전송하거나 읽지 않습니다. 모든 도구는 읽기 전용입니다.

| 도구 | 조회 내용 |
| --- | --- |
| `get_snapshot_status` | 게시 시각, 출처별 수집 상태와 건수 |
| `list_cves` | 현재 또는 아카이브 CVE 검색, 치명적 CVE·KEV·EPSS 보기 |
| `get_cve` | CVE 상세, 관련 공지와 변경 이력 |
| `list_news` | 뉴스, 국내 동향, KISA, 보안공지, 다크웹 관련 공개 보도 |
| `list_changes` | 신규 공개, KEV 등재, 패치·완화 변경 |
| `get_debian_packages` | CVE별 Debian 공개 패키지 정보 |

응답에는 게시 시각과 수집 상태가 포함됩니다. 아카이브는 각 항목의 `archivedAt`을 함께 확인하세요. 목록은 `limit`(최대 25)과 `offset`으로 페이지를 이동합니다.

## 초기 배포

Cloudflare 계정에서 Workers를 활성화하고, 저장소의 `mcp` 디렉터리에서 Wrangler를 실행합니다.

```sh
npx wrangler login
npx wrangler deploy
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put KEY_ENCRYPTION_SECRET
```

- 두 값은 각기 별도로 생성한 32바이트 랜덤 값을 64자 16진수로 준비합니다. 예를 들어 `openssl rand -hex 32`를 각각 실행합니다.
- Cloudflare 대시보드에서도 Worker의 **Settings → Variables and secrets**에서 두 값을 Secret으로 등록할 수 있습니다. 저장소 파일, 브라우저 URL, 로그에 값을 넣지 마세요.
- 암호화 비밀값은 별도로 보관합니다. 이 값을 교체하면 기존 키의 원문 조회가 실패하므로 기존 키를 폐기하고 다시 발급해야 합니다. 관리자 토큰 교체는 발급된 키에 영향을 주지 않습니다.
- 발급된 키의 원문은 Durable Object에 AES-GCM으로 암호화해 저장합니다. 호출 인증에는 SHA-256 해시를 사용합니다.

## 관리자 화면과 클라이언트 연결

1. 배포된 Worker의 `/admin`에서 관리자 토큰으로 인증합니다.
2. 사용처별로 키를 발급합니다. 목록은 접두사와 상태를 표시하며, **키 보기**로 활성 키 원문을 다시 조회할 수 있습니다. **폐기**한 키는 이후 인증이 거부됩니다.
3. Streamable HTTP와 사용자 정의 헤더를 지원하는 MCP 클라이언트에서 URL을 `https://<Worker 주소>/mcp`로 지정하고 `Authorization: Bearer <발급된 키>` 헤더를 설정합니다. 관리자 토큰은 클라이언트에 제공하지 않습니다.

이 배포는 Bearer 키 인증을 사용합니다. OAuth 전용 클라이언트와 다른 웹 출처에서 직접 요청하는 클라이언트는 지원하지 않습니다.

## 검증

```sh
node --test mcp/worker.test.mjs
```
