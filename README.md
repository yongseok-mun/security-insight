# Security Insight

한국어 다크 테마 보안 인텔리전스 대시보드. CVE 관제 화면에서 우선 점검 항목, 검색·필터·정렬, 영향 범위, 안전한 점검 절차, 출처 패널을 제공한다.

## 실행

```sh
npm run dev
```

브라우저에서 http://localhost:4173/ 을 연다. 일반 정적 호스팅에도 배치할 수 있다. `npm run check`는 JavaScript 구문을 확인한다.

## 데이터

현재 CVE, CVSS·EPSS·KEV 값과 뉴스는 모두 시안 데이터다. 출처 패널은 NVD, FIRST, CISA의 공식 사이트로 연결되며 실제 CVE의 검증 결과는 표시하지 않는다. 실시간 수집 및 내부 자산 연동은 추후 연결할 수 있다.
