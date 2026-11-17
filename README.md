# Security Insight

한국어 보안 인텔리전스 대시보드. CVE 우선순위, 영향 범위, 안전한 점검 절차와 뉴스 원문을 한 화면에서 확인한다.

## 실행

```sh
npm run dev
```

브라우저에서 http://localhost:4173/ 을 연다. `npm run check`로 JavaScript 구문을 확인하고 `python3 collect.py`로 스냅샷을 갱신한다.

## 수집과 배포

- cve.now 최신 목록을 NVD 최근 공개 데이터와 CVE ID로 결합한다. CISA KEV 신규 등재 항목도 살펴볼 수 있다. CVSS, EPSS와 KEV는 출처와 결측 상태를 함께 표시한다.
- 보호나라, 데일리시큐, ZDNet Korea, Google 뉴스, The Hacker News, BleepingComputer의 제목·발행 시각·원문 링크를 수집한다. ZDNet Korea는 Google 뉴스 RSS를 경유한다.
- GitHub Pages의 게시 소스를 **GitHub Actions**로 설정한다. 워크플로는 기본 브랜치 푸시, 수동 실행 및 두 시간 간격으로 수집해 정적 스냅샷을 배포한다. 이전 수집 상태는 캐시로 보존한다. 저장소의 `data.json`은 초기 스냅샷이다.
- 이 서비스는 NVD 데이터를 사용하며 NVD의 보증이나 인증을 받지 않았다.
