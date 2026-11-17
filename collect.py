#!/usr/bin/env python3
"""Refresh the public, read-only dashboard snapshot."""
import concurrent.futures
import datetime as dt
import email.utils
import html
import json
import os
from pathlib import Path
import re
import sys
import urllib.parse as url
import urllib.request as http
import xml.etree.ElementTree as xml

ROOT = Path(__file__).resolve().parent
KST = dt.timezone(dt.timedelta(hours=9))
NOW = dt.datetime.now(dt.timezone.utc)
CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
DARK = re.compile(r'다크웹|랜섬웨어|탈취.*판매|dark.?web|ransomware|leak site', re.I)
SECURITY = re.compile(r'보안|해킹|침해|취약점|랜섬웨어|정보.?유출|악성코드|사이버|security|CVE-', re.I)
GOOGLE = 'https://news.google.com/rss/search?'
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'


def google(query):
    return GOOGLE + url.urlencode(dict(q=query, hl='ko', gl='KR', ceid='KR:ko'))


FEEDS = {
    'KISA 보호나라 · 보안공지': ('https://www.boho.or.kr/kr/rss.do?bbsId=B0000133', 'advisory'),
    'KISA 보호나라 · 취약점 정보': ('https://www.boho.or.kr/kr/rss.do?bbsId=B0000302', 'advisory'),
    '데일리시큐': ('https://www.dailysecu.com/rss/allArticle.xml', 'news'),
    'ZDNet Korea': (google('site:zdnet.co.kr (보안 OR 취약점 OR 해킹 OR 랜섬웨어) when:14d'), 'aggregated'),
    'Google 뉴스': (google('(사이버보안 OR 취약점 OR 랜섬웨어 OR 정보유출) when:7d'), 'aggregated'),
    'The Hacker News': ('https://feeds.feedburner.com/TheHackersNews', 'news'),
    'BleepingComputer': ('https://www.bleepingcomputer.com/feed/', 'news'),
}


def get(address):
    headers = {'User-Agent': 'SecurityInsight/1.0 (public security feeds)'}
    if address.startswith(NVD) and os.environ.get('NVD_API_KEY'):
        headers['apiKey'] = os.environ['NVD_API_KEY']
    with http.urlopen(http.Request(address, headers=headers), timeout=22) as response:
        return response.read(16 * 1024 * 1024)


def clean(value):
    return ' '.join(html.unescape(re.sub(r'<[^>]+>', '', value or '')).split())


def timestamp(value):
    if not value:
        return None
    try:
        date = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        try:
            date = email.utils.parsedate_to_datetime(value)
        except ValueError:
            return None
    return date.replace(tzinfo=date.tzinfo or KST).isoformat()


def safe_url(value):
    try:
        parsed = url.urlsplit((value or '').strip())
    except ValueError:
        return None
    return parsed.geturl() if parsed.scheme in ('https', 'http') and parsed.hostname and not parsed.username else None


def rss(name, address, kind):
    root = xml.fromstring(get(address).strip())
    records = []
    for item in root.findall('.//item')[:50]:
        title = clean(item.findtext('title'))
        link = safe_url(item.findtext('link'))
        publisher = clean(item.findtext('source')) if kind == 'aggregated' else name
        if not title or not link or (kind == 'aggregated' and not SECURITY.search(title)):
            continue
        if kind == 'aggregated' and publisher and title.endswith(' - ' + publisher):
            title = title[:-(len(publisher) + 3)]
        records.append(dict(title=title, url=link, publisher=publisher or name, feed=name,
                            kind=kind, date=timestamp(item.findtext('pubDate', '').strip()),
                            korea=name not in ('The Hacker News', 'BleepingComputer'),
                            dark=bool(DARK.search(title)), cves=sorted(set(CVE.findall((title + ' ' + clean(item.findtext('description'))).upper())))))
    return records[:18]


def cve_now():
    rows = json.loads(get('https://cve.now/api/v1/entries?type=cve'))['items']
    return [v for v in rows if CVE.fullmatch(v.get('id', ''))]


def recent_kev(catalog):
    entries = sorted(catalog.values(), key=lambda item: item['dateAdded'], reverse=True)[:10]
    return [dict(id=item['cveID'], title=item['vulnerabilityName'],
                 product=f"{item['vendorProject']} {item['product']}", kev=True,
                 origin='CISA KEV') for item in entries]


def nvd_recent():
    start = (NOW - dt.timedelta(days=3)).strftime('%Y-%m-%dT%H:%M:%S.000')
    end = NOW.strftime('%Y-%m-%dT%H:%M:%S.000')
    params = url.urlencode(dict(pubStartDate=start, pubEndDate=end, resultsPerPage=2000))
    payload = json.loads(get(NVD + '?' + params))
    return {row['cve']['id']: row['cve'] for row in payload['vulnerabilities']}


def nvd_selected(ids):
    if not ids:
        return {}
    payload = json.loads(get(NVD + '?' + url.urlencode({'cveIds': ','.join(ids)})))
    return {row['cve']['id']: row['cve'] for row in payload['vulnerabilities']}


def metric(record):
    for name, version in [('cvssMetricV40', '4.0'), ('cvssMetricV31', '3.1'),
                          ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')]:
        values = record.get('metrics', {}).get(name, [])
        if values:
            selected = next((m for m in values if m.get('source') == 'nvd@nist.gov'), values[0])
            data = selected['cvssData']
            return data.get('baseScore'), version, data.get('vectorString'), selected.get('source')
    return None, None, None, None


def epss(ids):
    if not ids:
        return {}
    payload = json.loads(get('https://api.first.org/data/v1/epss?' + url.urlencode({'cve': ','.join(ids)})))
    return {row['cve']: dict(score=round(float(row['epss']) * 100, 2), date=row['date'])
            for row in payload['data']}


def normalize(item, record, kev, probability, news):
    cve_id = item['id']
    score, version, vector, provider = metric(record)
    kev_item = kev.get(cve_id)
    references = []
    for ref in record.get('references', []):
        address = safe_url(ref.get('url'))
        if address and ('Vendor Advisory' in ref.get('tags', []) or 'Patch' in ref.get('tags', [])):
            references.append(address)
    descriptions = {entry['lang']: clean(entry['value']) for entry in record.get('descriptions', [])}
    notices = [article for article in news if article['kind'] == 'advisory' and cve_id in article['cves']]
    return dict(id=cve_id, title=clean(item.get('title')) or cve_id,
                product=clean(item.get('product')) or None, published=timestamp(item.get('publishedAt') or record.get('published')),
                url=safe_url(item.get('url')), origin=item.get('origin', 'cve.now'), nvd=bool(record), nvdStatus=record.get('vulnStatus'),
                cvss=score if score is not None else item.get('cvss'),
                cvssSource=provider if score is not None else ('cve.now' if item.get('cvss') is not None else None),
                cvssVersion=version, vector=vector,
                epss=probability.get(cve_id), kev=cve_id in kev if kev else (True if item.get('kev') else None),
                kevDate=kev_item.get('dateAdded') if kev_item else None,
                description=descriptions.get('ko') or descriptions.get('en'),
                fixes=[clean(value) for value in item.get('fix', []) if isinstance(value, str)][:10],
                references=list(dict.fromkeys(references))[:5], notices=notices[:3])


def collect():
    path = ROOT / 'data.json'
    previous = json.loads(path.read_text()) if path.exists() else {}
    previous_feeds = previous.get('feeds', {})
    statuses = {}

    def attempt(name, job, fallback):
        try:
            result = job()
            statuses[name] = dict(state='ok', at=NOW.isoformat(), count=len(result))
            return result
        except (OSError, ValueError, KeyError, TypeError, xml.ParseError) as error:
            print(f'{name}: {error}', file=sys.stderr)
            prior = previous.get('sources', {}).get(name, {})
            statuses[name] = dict(state='stale' if fallback else 'unavailable', at=prior.get('at'), count=len(fallback))
            return fallback

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        feed_jobs = {name: pool.submit(attempt, name, lambda n=name, a=address, k=kind: rss(n, a, k),
                                       previous_feeds.get(name, []))
                     for name, (address, kind) in FEEDS.items()}
        now_job = pool.submit(attempt, 'cve.now', cve_now, [])
        nvd_job = pool.submit(attempt, 'NVD', nvd_recent, {})
        kev_job = pool.submit(attempt, 'CISA KEV', lambda: {
            row['cveID']: row for row in json.loads(get(KEV))['vulnerabilities']
        }, {})
        items = now_job.result()
        kev = kev_job.result()
        seen_ids = {item['id'] for item in items}
        items.extend(item for item in recent_kev(kev) if item['id'] not in seen_ids)
        probability_job = pool.submit(attempt, 'FIRST EPSS', lambda: epss([row['id'] for row in items]), {})
        feeds = {name: job.result() for name, job in feed_jobs.items()}
        nvd = nvd_job.result()
        missing = [item['id'] for item in items if item.get('origin') == 'CISA KEV' and item['id'] not in nvd]
        if missing:
            nvd.update(attempt('NVD · KEV 보강', lambda: nvd_selected(missing), {}))
        probability = probability_job.result()

    news, seen = [], set()
    for article in (a for feed in feeds.values() for a in feed):
        key = re.sub(r'[^\w]', '', article['title'].casefold())
        if article['url'] not in seen and key not in seen:
            news.append(article)
            seen.update((key, article['url']))
    news.sort(key=lambda a: dt.datetime.fromisoformat(a['date']).timestamp() if a['date'] else 0, reverse=True)
    records = [normalize(item, nvd.get(item['id'], {}), kev, probability, news) for item in items]
    if not seen_ids and previous.get('cves'):
        records = previous.get('cves', [])
        if records:
            statuses['cve.now'] = dict(previous['sources'].get('cve.now', {}), state='stale')
    if not records:
        raise SystemExit('No valid CVE snapshot available')
    snapshot = dict(updatedAt=NOW.isoformat(), cves=records, news=news, feeds=feeds, sources=dict(sorted(statuses.items())))
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    temp.replace(path)
    print(f'{len(records)} CVEs, {len(news)} linked news items')


if __name__ == '__main__':
    collect()
