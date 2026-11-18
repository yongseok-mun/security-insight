#!/usr/bin/env python3
"""Refresh the public, read-only dashboard snapshot."""
import concurrent.futures
import datetime as dt
from dataclasses import dataclass
import email.utils
import gzip
import html
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import urllib.parse as url
import urllib.request as http
import xml.etree.ElementTree as xml

ROOT = Path(__file__).resolve().parent
KST = dt.timezone(dt.timedelta(hours=9))
NOW = dt.datetime.now(dt.timezone.utc)
HISTORY_DAYS = 7
MAX_CVES = 140
NVD_EXTRA = 30
ARCHIVE_LIMIT = 1800
ARCHIVE_DAYS = 30
ARCHIVE_NEWS_LIMIT = 16
BRIEFING_NEWS_LIMIT = 12
VERSION_TOKEN = r'[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9+~_-]+(?:\.[A-Za-z0-9+~_-]+)*)?'
CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
DARK = re.compile(r'다크웹|랜섬웨어|탈취.*판매|dark.?web|ransomware|leak site', re.I)
SECURITY = re.compile(r'보안|해킹|침해|취약점|랜섬웨어|정보.?유출|악성코드|사이버|security|CVE-', re.I)
GOOGLE = 'https://news.google.com/rss/search?'
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
DEBIAN_TRACKER = 'https://security-tracker.debian.org/tracker/data/json'
DEBIAN_SUITES = ('bullseye', 'bookworm', 'trixie')
SOURCE_ERRORS = (OSError, ValueError, KeyError, TypeError, EOFError, xml.ParseError)
NVD_PAGE_SIZE = 2000
NVD_REQUEST_INTERVAL = 6
nvd_request_lock = threading.Lock()
next_nvd_request = 0.0


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
    if address.startswith(NVD):
        global next_nvd_request
        with nvd_request_lock:
            delay = next_nvd_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            next_nvd_request = time.monotonic() + NVD_REQUEST_INTERVAL
        if os.environ.get('NVD_API_KEY'):
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


MEDIA = '{http://search.yahoo.com/mrss/}'
ARTICLE_HOSTS = {'dailysecu.com', 'www.dailysecu.com', 'bleepingcomputer.com',
                 'www.bleepingcomputer.com', 'thehackernews.com', 'zdnet.co.kr', 'www.zdnet.co.kr'}


def image_url(value, base):
    address = safe_url(url.urljoin(base, (value or '').strip()))
    if address and url.urlsplit(address).scheme == 'https':
        return address
    return None


def feed_image(item, article_url):
    for node in item.iter():
        if node.tag == MEDIA + 'thumbnail' or (
            node.tag in ('enclosure', MEDIA + 'content') and (
                node.get('medium') == 'image' or node.get('type', '').startswith('image/')
            )
        ):
            address = image_url(node.get('url'), article_url)
            if node.get('url') and address:
                return address
    return None


def publisher_article(address):
    target = url.urlsplit(address)
    return (target.scheme == 'https' and target.hostname in ARTICLE_HOSTS
            and not target.username and target.port in (None, 443))


class PublisherRedirect(http.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        if not publisher_article(newurl):
            return None
        return super().redirect_request(request, fp, code, message, headers, newurl)


class ArticleImage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.images = {}

    def handle_starttag(self, tag, attrs):
        if tag != 'meta':
            return
        attributes = dict(attrs)
        property_name = (attributes.get('property') or attributes.get('name') or '').lower()
        if property_name in ('og:image', 'og:image:secure_url', 'twitter:image') and attributes.get('content'):
            self.images.setdefault(property_name, attributes['content'])


def article_image(address):
    try:
        opener = http.build_opener(PublisherRedirect())
        request = http.Request(address, headers={'User-Agent': 'SecurityInsight/1.0 (public article previews)'})
        with opener.open(request, timeout=6) as response:
            if response.headers.get_content_type() != 'text/html':
                return None
            parser = ArticleImage()
            parser.feed(response.read(192 * 1024).decode(response.headers.get_content_charset() or 'utf-8', errors='replace'))
            for name in ('og:image:secure_url', 'og:image', 'twitter:image'):
                if name in parser.images:
                    image = image_url(parser.images[name], response.url)
                    if image:
                        return image
    except (OSError, ValueError, LookupError):
        pass
    return None


def add_article_images(feeds, previous_feeds):
    cached = {entry['url']: entry['image'] for entries in previous_feeds.values()
              for entry in entries if entry.get('image')}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = {}
        for article in (entry for entries in feeds.values() for entry in entries):
            address = article['url']
            image = article.get('image') or cached.get(address)
            if image:
                article['image'] = image
            elif publisher_article(address):
                if address not in pending:
                    pending[address] = (pool.submit(article_image, address), [])
                pending[address][1].append(article)
        for job, articles in pending.values():
            image = job.result()
            if image:
                for article in articles:
                    article['image'] = image


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
                            kind=kind, image=feed_image(item, link), date=timestamp(item.findtext('pubDate', '').strip()),
                            korea=name not in ('The Hacker News', 'BleepingComputer'),
                            dark=bool(DARK.search(title)), cves=sorted(set(CVE.findall((title + ' ' + clean(item.findtext('description'))).upper())))))
    return records[:18]


def cve_now():
    rows = json.loads(get('https://cve.now/api/v1/entries?type=cve'))['items']
    return [v for v in rows if CVE.fullmatch(v.get('id', ''))]


def recent_kev(catalog):
    entries = sorted(catalog.values(), key=lambda item: item['dateAdded'], reverse=True)
    cutoff = (NOW - dt.timedelta(days=HISTORY_DAYS)).date().isoformat()
    entries = [item for index, item in enumerate(entries) if index < 10 or item['dateAdded'] >= cutoff]
    return [dict(id=item['cveID'], title=item['vulnerabilityName'],
                 product=f"{item['vendorProject']} {item['product']}", kev=True,
                 origin='CISA KEV') for item in entries]


@dataclass
class NvdWindow:
    records: dict
    expected: int
    error: str | None = None


def nvd_recent(modified=False):
    start = (NOW - (dt.timedelta(hours=24) if modified else dt.timedelta(days=3))).strftime('%Y-%m-%dT%H:%M:%S.000')
    end = NOW.strftime('%Y-%m-%dT%H:%M:%S.000')
    prefix = 'lastMod' if modified else 'pub'
    params = {prefix + 'StartDate': start, prefix + 'EndDate': end, 'resultsPerPage': NVD_PAGE_SIZE}
    records = {}
    expected = None
    offset = 0
    while True:
        try:
            payload = json.loads(get(NVD + '?' + url.urlencode({**params, 'startIndex': offset})))
            total = payload['totalResults']
            rows = payload['vulnerabilities']
            if type(total) is not int or total < 0 or payload['startIndex'] != offset:
                raise ValueError('NVD returned invalid pagination metadata')
            if expected is None:
                expected = total
            if total != expected or len(rows) != min(NVD_PAGE_SIZE, expected - offset):
                raise ValueError('NVD page size or total changed during collection')
            page = {row['cve']['id']: row['cve'] for row in rows}
            if len(page) != len(rows) or records.keys() & page.keys():
                raise ValueError('NVD returned duplicate CVE IDs across the window')
            records.update(page)
        except SOURCE_ERRORS as error:
            if expected is None:
                raise
            return NvdWindow(records, expected, str(error))
        offset += len(rows)
        if offset == expected:
            return NvdWindow(records, expected)


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
    scores = {}
    for start in range(0, len(ids), 70):
        batch = ','.join(ids[start:start + 70])
        payload = json.loads(get('https://api.first.org/data/v1/epss?' + url.urlencode({'cve': batch})))
        scores.update({row['cve']: dict(score=round(float(row['epss']) * 100, 2), date=row['date'])
                       for row in payload['data']})
    return scores



CVE_LIST = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves'


def cna_record(cve_id):
    _, year, number = cve_id.split('-')
    path = f'{year}/{int(number) // 1000 if len(number) > 4 else number[0]}xxx/{cve_id}.json'
    try:
        payload = json.loads(get(f'{CVE_LIST}/{path}'))
        if payload['cveMetadata']['cveId'] == cve_id and payload['cveMetadata']['state'] == 'PUBLISHED':
            return payload['containers']['cna']
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'{cve_id} CNA: {error}', file=sys.stderr)
    return None


def localized(container, field, lang):
    return list(dict.fromkeys(clean(entry['value']) for entry in container.get(field, [])
                             if entry.get('lang', '').split('-')[0] == lang and entry.get('value')))


def cna_details(container):
    affected = []
    for product in container.get('affected', []):
        versions = []
        for entry in product.get('versions', []):
            versions.append({key: entry[key] for key in
                             ('version', 'versionType', 'lessThan', 'lessThanOrEqual', 'status', 'changes')
                             if key in entry})
        affected.append(dict(
            vendor=clean(product.get('vendor')), product=clean(product.get('product') or product.get('packageName')),
            platforms=product.get('platforms', []), modules=product.get('modules', []),
            programFiles=product.get('programFiles', []),
            defaultStatus=product.get('defaultStatus', 'unknown'), versions=versions,
        ))
    return dict(
        provider=container.get('providerMetadata', {}).get('shortName'),
        versionTypesCollected=True,
        affected=affected,
        solutions=localized(container, 'solutions', 'ko') or localized(container, 'solutions', 'en'),
        workarounds=localized(container, 'workarounds', 'ko') or localized(container, 'workarounds', 'en'),
        references=list(dict.fromkeys(address for entry in container.get('references', [])
                                      if 'vendor-advisory' in [tag.lower() for tag in entry.get('tags', [])]
                                      and (address := safe_url(entry.get('url')))))[:5],
    )


def enrich_cves(records, previous, translations):
    old_rows = {entry['id']: entry for entry in previous.get('cves', [])}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        def enrich(item):
            old = old_rows.get(item['id'], {})
            cna = None
            # Keep unchanged records warm for six hours, then recheck editorial revisions.
            last_checked = old.get('cnaChecked')
            if (last_checked and (old.get('cna') or {}).get('versionTypesCollected')
                    and NOW - dt.datetime.fromisoformat(last_checked) < dt.timedelta(hours=6)):
                item.update({key: old[key] for key in ('cna', 'cnaChecked', 'cnaEnglish', 'cnaKorean', 'cnaTitle') if key in old})
            else:
                cna = cna_record(item['id'])
                if cna:
                    item['cna'] = cna_details(cna)
                    item['cnaChecked'] = NOW.isoformat()
                    item['cnaTitle'] = clean(cna.get('title'))
                    item['cnaEnglish'] = next(iter(localized(cna, 'descriptions', 'en')), None)
                    item['cnaKorean'] = next(iter(localized(cna, 'descriptions', 'ko')), None)
                elif old.get('cna'):
                    item.update({key: old[key] for key in ('cna', 'cnaChecked', 'cnaEnglish', 'cnaKorean', 'cnaTitle') if key in old})
            cna_info = item.get('cna') or {}
            affected = cna_info.get('affected', [])
            if not item.get('product') and affected:
                item['product'] = affected[0].get('product') or None
            if item['title'] == item['id']:
                item['title'] = item.get('cnaTitle') or item.get('product') or item['id']
            english = item.get('descriptionEn') or item.get('cnaEnglish')
            if not item.get('descriptionEn') and item.get('cnaEnglish'):
                item['descriptionEnSource'] = 'CNA'
            korean = (item.get('descriptionKo') if item.get('translationSource') != '한국어 요약' else None) or item.get('cnaKorean')
            documented = translations.get(item['id'], {})
            if english and documented.get('sha256') != hashlib.sha256(english.encode('utf-8')).hexdigest():
                documented = {}
            item['titleKo'] = documented.get('title') if english else None
            if korean:
                item['translationSource'] = '공식 레코드'
            elif english and documented.get('summary'):
                korean = documented['summary']
                item['translationSource'] = '한국어 요약'
            explicit_fixes = re.findall(
                r'\b(?:fixed|patched|resolved) in version v?([0-9][0-9A-Za-z.+-]*[0-9A-Za-z])\b',
                english or '', flags=re.IGNORECASE)
            item['describedFixes'] = list(dict.fromkeys(explicit_fixes))
            item['descriptionEn'] = english
            item['descriptionKo'] = korean
            item['description'] = english or korean
            return item
        return list(pool.map(enrich, records))


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
                descriptionEn=descriptions.get('en'), descriptionKo=descriptions.get('ko'),
                descriptionEnSource='NVD' if descriptions.get('en') else None,
                nvdConfigurations=record.get('configurations', []),
                requiredAction=clean(kev_item.get('requiredAction')) if kev_item else None,
                fixes=[clean(value) for value in item.get('fix', []) if isinstance(value, str)][:10],
                references=list(dict.fromkeys(references))[:5], notices=notices[:3])


def moment(value):
    normalized = timestamp(value)
    return dt.datetime.fromisoformat(normalized) if normalized else None


def debian_packages(tracker, cve_ids=None):
    matches = {}
    for package, issues in tracker.items():
        for cve_id in cve_ids.intersection(issues) if cve_ids is not None else issues:
            if not CVE.fullmatch(cve_id):
                continue
            releases = issues[cve_id].get('releases', {})
            for suite in DEBIAN_SUITES:
                entry = releases.get(suite, {})
                fixed = entry.get('fixed_version')
                if entry.get('status') == 'resolved' and isinstance(fixed, str) and fixed != '0' and re.match(r'^[0-9]', fixed):
                    matches.setdefault(cve_id, []).append(dict(package=package, suite=suite, fixed=fixed))
    return matches


def fetch_debian_packages():
    request = http.Request(DEBIAN_TRACKER, headers={
        'Accept-Encoding': 'gzip', 'User-Agent': 'SecurityInsight/1.0 (public security feeds)',
    })
    limit = 128 * 1024 * 1024
    with http.urlopen(request, timeout=28) as response:
        if response.headers.get('Content-Encoding') == 'gzip':
            with gzip.GzipFile(fileobj=response) as decoded:
                payload = decoded.read(limit + 1)
        else:
            payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError('Debian tracker exceeds the expected maximum size')
    return debian_packages(json.loads(payload))


def briefing_coverage(articles):
    cutoff = NOW - dt.timedelta(hours=72)
    coverage = {}
    for article in articles:
        date = moment(article.get('date'))
        publisher = re.sub(r'[^\w]', '', article.get('publisher', '').casefold())
        if (not publisher or not date or not cutoff <= date <= NOW
                or (article['kind'] == 'aggregated' and article['publisher'] == article.get('feed'))):
            continue
        for cve_id in article['cves']:
            entry = coverage.setdefault(cve_id, {'news': set(), 'official': False, 'latest': date})
            if article['kind'] == 'advisory':
                entry['official'] = True
            else:
                entry['news'].add(publisher)
            entry['latest'] = max(entry['latest'], date)
    ranked = [(key, value) for key, value in coverage.items()
              if len(value['news']) >= (1 if value['official'] else 2)]
    ranked.sort(key=lambda pair: (-int(pair[1]['official']), -len(pair[1]['news']),
                                  -pair[1]['latest'].timestamp(), pair[0]))
    return {key: {'official': value['official'], 'publishers': len(value['news']),
                  'latest': value['latest'].isoformat()}
            for key, value in ranked[:BRIEFING_NEWS_LIMIT]}


def candidates(feed, nvd, kev, previous, modified=None, briefing_ids=(), known_briefing=None):
    previous_at = previous.get('updatedAt')
    cutoff = NOW - dt.timedelta(days=HISTORY_DAYS)
    feed_by_id = {item['id']: item for item in feed}
    items = {}
    kev_items = recent_kev(kev)
    for item in kev_items:
        current_feed = feed_by_id.get(item['id'])
        items[item['id']] = {**item, **current_feed, 'origin':'cve.now', 'lastDiscoveredAt':NOW.isoformat()} if current_feed else {
            **item, 'lastDiscoveredAt':NOW.isoformat()}
    for cve_id in briefing_ids:
        record = (modified or {}).get(cve_id) or nvd.get(cve_id)
        cached = (known_briefing or {}).get(cve_id)
        if cve_id not in items and (cve_id in feed_by_id or record or cached):
            seed = feed_by_id.get(cve_id) or dict(id=cve_id, origin=(cached or {}).get('origin', 'NVD'),
                                                publishedAt=(record or {}).get('published'))
            items[cve_id] = {**seed, 'lastDiscoveredAt':NOW.isoformat()}
    published = sorted(nvd.values(), key=lambda item: item.get('published') or '', reverse=True)
    recent_changes = sorted((modified or {}).values(), key=lambda item: item.get('lastModified') or '', reverse=True)
    for source, quota in ((published, NVD_EXTRA), (recent_changes, NVD_EXTRA // 2)):
        extra = 0
        for item in source:
            if item['id'] in items or item['id'] in feed_by_id or item.get('vulnStatus', '').lower() == 'rejected':
                continue
            items[item['id']] = dict(id=item['id'], origin='NVD', publishedAt=item.get('published'),
                                     lastDiscoveredAt=NOW.isoformat())
            extra += 1
            if extra >= quota:
                break
    for item in feed:
        items.setdefault(item['id'], {**item, 'lastDiscoveredAt': NOW.isoformat()})
    for old in previous.get('cves', []):
        retained_at = old.get('lastDiscoveredAt') or previous_at
        if retained_at and moment(retained_at) >= cutoff:
            items.setdefault(old['id'], dict(id=old['id'], origin=old.get('origin', 'cve.now'),
                                            lastDiscoveredAt=retained_at))
    return [item for item in items.values()
            if ((modified or {}).get(item['id']) or nvd.get(item['id'], {})).get('vulnStatus', '').lower() != 'rejected'][:max(MAX_CVES, len(kev_items))]


def merge_record(item, old, nvd, kev, probability, news, statuses):
    cve_id = item['id']
    nvd_record = nvd.get(cve_id, {})
    current = normalize(item, nvd_record, kev, probability, news)
    stamps = dict(old.get('sourceTimes', {}))
    current['lastDiscoveredAt'] = item['lastDiscoveredAt']
    for key in ('title', 'product', 'url', 'published'):
        if (not current.get(key) or ('title' not in item and key == 'title')) and old.get(key):
            current[key] = old[key]
    if item.get('origin') != 'cve.now' and old.get('origin') == 'cve.now':
        current['origin'] = 'cve.now'
    if item.get('origin', 'cve.now') == 'cve.now' and 'title' in item:
        stamps['cve.now'] = statuses['cve.now']['at']
    else:
        current['fixes'] = old.get('fixes', current['fixes'])
    if nvd_record:
        source = 'NVD · KEV 보강' if cve_id in statuses.get('nvdSupplementIds', ()) else 'NVD'
        stamps['NVD'] = statuses[source]['at']
    elif old.get('nvd'):
        for key in ('nvd', 'nvdStatus', 'references', 'descriptionEn', 'descriptionEnSource', 'nvdConfigurations'):
            current[key] = old.get(key)
        current['descriptionKo'] = old.get('descriptionKo') if old.get('translationSource') == '공식 레코드' else None
    if current['cvss'] is None or (not nvd_record and old.get('cvssSource') not in (None, 'cve.now')):
        for key in ('cvss', 'cvssSource', 'cvssVersion', 'vector'):
            current[key] = old.get(key)
    if statuses['CISA KEV']['state'] == 'ok':
        stamps['CISA KEV'] = statuses['CISA KEV']['at']
    elif old.get('kev') is not None:
        for key in ('kev', 'kevDate', 'requiredAction'):
            current[key] = old.get(key)
    epss_ok = statuses['FIRST EPSS']['state'] == 'ok'
    if current['epss']:
        current['epssStatus'] = 'ok'
        stamps['FIRST EPSS'] = statuses['FIRST EPSS']['at']
    elif not epss_ok and old.get('epss') is not None:
        current['epss'] = old['epss']
        current['epssStatus'] = 'stale'
    else:
        current['epssStatus'] = 'missing' if epss_ok else 'unavailable'
    current['sourceTimes'] = stamps
    return current


def impact_values(item):
    cna = item.get('cna') or {}
    impact = []
    statuses = {'affected':'영향받음', 'unaffected':'영향 없음', 'unknown':'미확인'}
    for product in cna.get('affected', []):
        identity = ' / '.join(filter(None, [product.get('vendor'), product.get('product')])) or '제품 미확인'
        for key, label in [('platforms','플랫폼'), ('modules','구성요소'), ('programFiles','프로그램 파일')]:
            if product.get(key):
                impact.append(f"{identity} · {label}: {', '.join(sorted(set(product[key])))}")
        default = product.get('defaultStatus', 'unknown')
        impact.append(f'{identity} · 목록 외 버전: {statuses.get(default, default)}')
        for entry in product.get('versions', []):
            status = entry.get('status', 'unknown')
            lower, exclusive, inclusive = [entry.get(key) for key in ('version','lessThan','lessThanOrEqual')]
            bounds = ' / '.join(filter(None, [
                ('최초 버전부터' if lower == '0' else f'{lower} 이상') if (exclusive or inclusive) else lower,
                f'{exclusive} 미만' if exclusive else '', f'{inclusive} 이하' if inclusive else '',
            ]))
            changes = sorted(f"{change.get('at')} → {statuses.get(change.get('status'), '미확인')}" for change in entry.get('changes', []))
            impact.append(' · '.join(filter(None, [identity, statuses.get(status, status), bounds, entry.get('versionType'), *changes])))

    def nvd_conditions(node, parent=()):
        logic = (*parent, str(node.get('operator') or 'OR') + (' (부정)' if node.get('negate') else ''))
        for entry in node.get('cpeMatch', []):
            bounds = [f'{entry[key]} {label}' for key, label in (
                ('versionStartIncluding','이상'), ('versionStartExcluding','초과'),
                ('versionEndIncluding','이하'), ('versionEndExcluding','미만')) if entry.get(key)]
            yield ' · '.join(['NVD', ' / '.join(logic), '취약 대상' if entry.get('vulnerable') else '환경 조건',
                              entry.get('criteria', ''), *bounds])
        for child in node.get('nodes', []) or node.get('children', []):
            yield from nvd_conditions(child, logic)

    for configuration in item.get('nvdConfigurations') or []:
        impact.extend(nvd_conditions(configuration))
    vector = item.get('vector') or ''
    if vector.startswith(('CVSS:3.', 'CVSS:4.')):
        conditions = sorted(metric for metric in vector.split('/') if metric.split(':')[0] in ('AV','AC','AT','PR','UI'))
        if conditions:
            impact.append('CVSS 전제조건 · ' + ' / '.join(conditions))
    return sorted(set(impact))


def patch_evidence(item):
    cve_id = item['id']
    cna = f'https://www.cve.org/CVERecord?id={cve_id}'
    nvd = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    evidence = []
    for value in item.get('fixes', []):
        if re.fullmatch(VERSION_TOKEN, value):
            evidence.append(dict(version=value, source='cve.now 수정 정보', url=item.get('url'), text=value))
    fixed = re.compile(rf'\b(?:fixed|patched|resolved)\s+in\s+(?:version\s+)?v?({VERSION_TOKEN})(?![\w+~-]|\.\d)', re.I)
    upgrade = re.compile(rf'\b(?:upgrade|update)\s+to\s+(?:version\s+)?v?({VERSION_TOKEN})(?![\w+~-]|\.\d)', re.I)
    affected = (item.get('cna') or {}).get('affected', [])

    def add_from_text(text, source, address, patterns):
        for sentence in re.split(r'(?<=[.!?;])\s+|[\r\n]+', text):
            for pattern in patterns:
                for match in pattern.finditer(sentence.rstrip('.')):
                    # Keep negated or conditional wording in the original advisory.
                    if re.search(r'\b(?:not|never|unconfirmed|might|may|expected|planned)\b', sentence, re.I):
                        continue
                    scope = [index for index, product in enumerate(affected)
                             if len(name := product.get('product', '')) >= 4
                             and re.search(rf'(?<!\w){re.escape(name)}(?!\w)', sentence, re.I)]
                    evidence.append(dict(version=match[1], source=source, url=address,
                                         text=sentence[:2400], **({'productIndex': scope[0]} if len(scope) == 1 else {})))

    source = item.get('descriptionEnSource')
    if source in ('NVD', 'CNA'):
        add_from_text(item.get('descriptionEn') or '', f'{source} 설명 명시',
                      nvd if source == 'NVD' else cna, [fixed])
    for solution in (item.get('cna') or {}).get('solutions', []):
        add_from_text(solution, 'CNA 해결책 명시', cna, [fixed, upgrade])
    seen = set()
    unique = []
    for entry in evidence:
        key = (entry['version'], entry['source'], entry['url'], entry.get('productIndex'))
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


class AdvisoryTable(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = None
        self.cell = None
        self.columns = None
        self.table = False

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            self.table = True
            self.columns = None
        elif self.table and tag == 'tr':
            self.row = []
        elif self.row is not None and tag in ('td', 'th'):
            self.cell = []
            if any(key in ('rowspan', 'colspan') and value != '1' for key, value in attrs):
                self.row.append('')  # Skip merged cells rather than guess their meaning.
        elif self.cell is not None and tag == 'br':
            self.cell.append(' ')

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None and self.row is not None:
            self.row.append(' '.join(''.join(self.cell).split()))
            self.cell = None
        elif tag == 'tr' and self.row is not None:
            if len(self.row) == 4:
                columns = [''.join(value.split()) for value in self.row]
                required = ('취약점', '제품명', '영향받는버전', '해결버전')
                if set(columns) == set(required):
                    self.columns = [columns.index(label) for label in required]
                elif self.columns:
                    cve, product, affected, fixed = (self.row[index] for index in self.columns)
                    if CVE.fullmatch(cve) and all((product, affected, fixed)):
                        self.rows.append(dict(id=cve.upper(), product=product, affected=affected, fixed=fixed))
            self.row = None
            self.cell = None
        elif tag == 'table':
            self.table = False


def kisa_patch_rows(address):
    parsed = url.urlsplit(address)
    if (parsed.scheme != 'https' or parsed.hostname not in {
        'www.krcert.or.kr', 'krcert.or.kr', 'www.boho.or.kr', 'boho.or.kr'
    } or parsed.port not in (None, 443) or parsed.path != '/kr/bbs/view.do'):
        raise ValueError('unexpected KISA advisory address')
    parser = AdvisoryTable()
    parser.feed(get(address).decode('utf-8-sig'))
    parser.close()
    return parser.rows


def enrich_kisa_notices(feeds, previous_feeds):
    articles = sorted((article for group in feeds.values() for article in group
                       if article['kind'] == 'advisory' and article.get('date')),
                      key=lambda article: moment(article['date']), reverse=True)[:12]
    previous = {article['url']: article.get('officialRows', [])
                for group in previous_feeds.values() for article in group}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {article['url']: pool.submit(kisa_patch_rows, article['url']) for article in articles}
        for article in articles:
            address = article['url']
            try:
                rows = jobs[address].result()
            except SOURCE_ERRORS as error:
                print(f'KISA advisory table: {error}', file=sys.stderr)
                rows = []
            article['officialRows'] = rows or previous.get(address, [])
            article['officialRowsFresh'] = bool(rows)
            article['cves'] = sorted(set(article['cves']) | {row['id'] for row in article['officialRows']})


def apply_official_patches(item, old, news):
    updated_urls = {article['url'] for article in news if article.get('officialRows')}
    entries = [{**row, 'fresh':False} for row in old.get('officialPatches', []) if row['url'] not in updated_urls]
    entries.extend(dict(product=row['product'], affected=row['affected'], fixed=row['fixed'], url=article['url'], fresh=article.get('officialRowsFresh', False))
                   for article in news for row in article.get('officialRows', [])
                   if row['id'] == item['id'])
    unique = {(row['product'], row['affected'], row['fixed'], row['url']):row for row in entries}
    if unique:
        item['officialPatches'] = [unique[key] for key in sorted(unique)]
    else:
        item.pop('officialPatches', None)


def annotate_review_fields(item):
    item['impactScope'] = impact_values(item)
    item['patchEvidence'] = patch_evidence(item)


def featured_news_cves(news, active_ids):
    ranks = {}
    for article in news:
        for cve_id in article['cves']:
            if cve_id in active_ids:
                continue
            advisory, count = ranks.get(cve_id, (False, 0))
            ranks[cve_id] = (advisory or article['kind'] == 'advisory', count + 1)
    return sorted(ranks, key=lambda cve_id: ranks[cve_id], reverse=True)[:ARCHIVE_NEWS_LIMIT]


def build_archive(previous, prior_active, nvd, feed, active, kev, debian, news, translations):
    cutoff = NOW - dt.timedelta(days=ARCHIVE_DAYS)
    archive = {**previous, **prior_active}
    active_ids = {item['id'] for item in active}
    sources = {item['id']: item for item in feed}
    featured_ids = featured_news_cves(news, active_ids)
    official_ids = {row['id'] for article in news for row in article.get('officialRows', []) if row['id'] in archive}
    for cve_id in set(nvd) | set(sources) | set(featured_ids) | official_ids:
        record = nvd.get(cve_id, {})
        if record.get('vulnStatus', '').lower() == 'rejected':
            archive.pop(cve_id, None)
            continue
        if cve_id in active_ids:
            continue
        item = normalize(sources.get(cve_id, {'id':cve_id, 'origin':'NVD'}), record, kev, {}, news)
        item['description'] = item.get('descriptionEn') or item.get('descriptionKo')
        item['archivedAt'] = NOW.isoformat()
        if debian.get(cve_id):
            item['debianPackages'] = debian[cve_id]
        # Keep CNA enrichment for items observed previously in the active list.
        old = archive.get(cve_id) or {}
        if item['title'] == cve_id and old.get('title'):
            item['title'] = old['title']
        if not item['product'] and old.get('product'):
            item['product'] = old['product']
        for key in ('cna', 'cnaChecked', 'cnaTitle', 'cnaEnglish', 'cnaKorean'):
            if key in old:
                item[key] = old[key]
        if not record and cve_id not in sources:
            item = {**(old or item), 'archivedAt': NOW.isoformat()}
            item['notices'] = [article for article in news if article['kind'] == 'advisory' and cve_id in article['cves']][:3]
            if debian.get(cve_id):
                item['debianPackages'] = debian[cve_id]
        apply_official_patches(item, old, news)
        annotate_review_fields(item)
        archive[cve_id] = item

    cached = {**previous, **prior_active}
    supplements = [archive[cve_id] for cve_id in featured_ids if cve_id in archive]
    for item in enrich_cves(supplements, {'cves': [cached[cve_id] for cve_id in featured_ids if cve_id in cached]}, translations):
        if not item.get('nvd') and item['id'] not in sources and not item.get('cnaChecked'):
            archive.pop(item['id'], None)
            continue
        annotate_review_fields(item)
        archive[item['id']] = item

    retained = []
    for key, item in archive.items():
        seen = moment(item.get('archivedAt') or item.get('lastDiscoveredAt'))
        if key not in active_ids and seen and seen >= cutoff:
            retained.append((key, {**item, 'archivedAt':seen.isoformat()}))
    featured = set(featured_ids)
    retained.sort(key=lambda pair: (pair[0] in featured, pair[1]['archivedAt'], pair[0]), reverse=True)
    return dict(retained[:ARCHIVE_LIMIT])


def remediation_values(item):
    cna = item.get('cna') or {}
    return {
        '패치 버전': sorted(set(item.get('fixes', []) + item.get('describedFixes', []))),
        '해결책': sorted(set(cna.get('solutions', []))),
        '완화책': sorted(set(cna.get('workarounds', []))),
        'CISA 조치 권고': [item['requiredAction']] if item.get('requiredAction') else [],
        '영향 버전·조건': item.get('impactScope') if 'impactScope' in item else impact_values(item),
        '공식 제품별 패치 기준': sorted(set(
            f"{row['product']} · 영향 {row['affected']} → 해결 {row['fixed']} · {row['url']}"
            for row in item.get('officialPatches', []))),
        'Debian 수정 패키지': sorted(
            f"{entry['suite']} / {entry['package']} · {entry['fixed']}" for entry in item.get('debianPackages', [])),
    }


def build_history(records, previous):
    cutoff = NOW - dt.timedelta(days=HISTORY_DAYS)
    previous_at = moment(previous.get('updatedAt'))
    old_rows = {item['id']: item for item in previous.get('cves', [])}
    history = [event for event in previous.get('history', []) if moment(event['at']) >= cutoff]
    seen = {(event['id'], event['type'], event['at']) for event in history}

    def add(item, kind, when, changes=None, day_only=False):
        when = moment(when)
        if not when or (when.date() < cutoff.date() if day_only else when < cutoff):
            return
        at = when.date().isoformat() if day_only else when.astimezone(dt.timezone.utc).isoformat()
        key = (item['id'], kind, at)
        if key in seen:
            return
        seen.add(key)
        history.append(dict(id=item['id'], title=item['title'], type=kind, at=at, changes=changes or []))

    for item in records:
        old = old_rows.get(item['id'])
        # The first release can reconstruct dates published by the sources.
        if not old or 'history' not in previous:
            add(item, 'published', item.get('published'))
        if item.get('kev') is True and item.get('kevDate'):
            add(item, 'kev', item['kevDate'], day_only=True)
        if old:
            before, after = remediation_values(old), remediation_values(item)
            changes = [dict(field=key, before=before[key], after=after[key]) for key in after
                       if before[key] != after[key]]
            if changes and previous_at:
                add(item, 'remediation', NOW.isoformat(), changes)
    return sorted(history, key=lambda event: moment(event['at']), reverse=True)


def collect_source(name, job, fallback, previous_status, retry=False):
    best_partial = None
    attempts = 2 if retry else 1
    for number in range(1, attempts + 1):
        try:
            result = job()
            if isinstance(result, NvdWindow):
                if result.error is not None:
                    if best_partial is None or len(result.records) >= len(best_partial.records):
                        best_partial = result
                    raise ValueError(result.error)
                return result.records, dict(state='ok', at=NOW.isoformat(), count=len(result.records),
                                            expected=result.expected, attempts=number)
            if not result and name in ('cve.now', 'CISA KEV', 'Debian Security Tracker', *FEEDS):
                raise ValueError('empty upstream feed')
            return result, dict(state='ok', at=NOW.isoformat(), count=len(result), attempts=number)
        except SOURCE_ERRORS as error:
            print(f'{name} (attempt {number}/{attempts}): {error}', file=sys.stderr)
            if number < attempts:
                time.sleep(8)
    if best_partial is not None:
        return best_partial.records, dict(state='partial', at=NOW.isoformat(), count=len(best_partial.records),
                                          expected=best_partial.expected, lastSuccessfulAt=previous_status.get('lastSuccessfulAt')
                                          or (previous_status.get('at') if previous_status.get('state') != 'partial' else None),
                                          attempts=attempts)
    return fallback, dict(state='stale' if fallback else 'unavailable',
                          at=previous_status.get('lastSuccessfulAt')
                          or (previous_status.get('at') if previous_status.get('state') != 'partial' else None),
                          count=len(fallback), attempts=attempts)


def collect():
    path = ROOT / 'data.json'
    previous = json.loads(path.read_text()) if path.exists() else {}
    previous_feeds = previous.get('feeds', {})
    statuses = {}
    debian_cache = ROOT / '.feed-cache' / 'debian-packages.json'
    try:
        previous_debian = json.loads(debian_cache.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        previous_debian = {}
    archive_cache = ROOT / '.feed-cache' / 'cve-archive.json'
    try:
        previous_archive = json.loads(archive_cache.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        previous_archive = {}

    morning = 6 <= NOW.astimezone(KST).hour < 8

    def attempt(name, job, fallback):
        result, status = collect_source(name, job, fallback, previous.get('sources', {}).get(name, {}), retry=morning)
        statuses[name] = status
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        feed_jobs = {name: pool.submit(attempt, name, lambda n=name, a=address, k=kind: rss(n, a, k),
                                       previous_feeds.get(name, []))
                     for name, (address, kind) in FEEDS.items()}
        now_job = pool.submit(attempt, 'cve.now', cve_now, [])
        nvd_job = pool.submit(attempt, 'NVD', nvd_recent, {})
        nvd_changes_job = pool.submit(attempt, 'NVD · 최근 수정', lambda: nvd_recent(modified=True), {})
        kev_job = pool.submit(attempt, 'CISA KEV', lambda: {
            row['cveID']: row for row in json.loads(get(KEV))['vulnerabilities']
        }, {})
        feed = now_job.result()
        kev = kev_job.result()
        nvd = nvd_job.result()
        modified = nvd_changes_job.result()
        old_rows = {entry['id']: entry for entry in previous.get('cves', [])}
        debian_job = pool.submit(attempt, 'Debian Security Tracker', fetch_debian_packages, previous_debian)
        if statuses['cve.now']['state'] == 'unavailable' and any(row.get('origin') == 'cve.now' for row in old_rows.values()):
            prior = previous.get('sources', {}).get('cve.now', {})
            statuses['cve.now'].update(state='stale', count=prior.get('count', 0))
        feeds = {name: job.result() for name, job in feed_jobs.items()}
        enrich_kisa_notices(feeds, previous_feeds)
        coverage = briefing_coverage(article for group in feeds.values() for article in group)
        known_briefing = {key: row for key in coverage if
                          (row := old_rows.get(key) or previous_archive.get(key))
                          and (row.get('nvd') or row.get('cnaChecked'))}
        for key, row in known_briefing.items():
            old_rows.setdefault(key, row)
        feed_ids = {row['id'] for row in feed}
        missing_briefing = [key for key in coverage if key not in feed_ids and key not in nvd and key not in modified]
        if missing_briefing:
            try:
                nvd.update(nvd_selected(missing_briefing))
            except SOURCE_ERRORS as error:
                print(f'NVD briefing supplement: {error}', file=sys.stderr)
        items = candidates(feed, nvd, kev, previous, modified, coverage, known_briefing)
        nvd.update(modified)
        probability_job = pool.submit(attempt, 'FIRST EPSS', lambda: epss([row['id'] for row in items]), {})
        missing = [item['id'] for item in items if item['id'] in kev and item['id'] not in nvd]
        supplement = attempt('NVD · KEV 보강', lambda: nvd_selected(missing), {}) if missing else {}
        nvd.update(supplement)
        probability = probability_job.result()
        debian = debian_job.result()

    add_article_images(feeds, previous_feeds)
    news, seen = [], set()
    for article in (a for feed in feeds.values() for a in feed):
        key = re.sub(r'[^\w]', '', article['title'].casefold())
        if article['url'] not in seen and key not in seen:
            news.append(article)
            seen.update((key, article['url']))
    news.sort(key=lambda a: dt.datetime.fromisoformat(a['date']).timestamp() if a['date'] else 0, reverse=True)
    merge_status = {**statuses, 'nvdSupplementIds': supplement.keys()}
    records = [merge_record(item, old_rows.get(item['id'], {}), nvd, kev, probability, news, merge_status)
               for item in items]
    for record in records:
        if record['id'] in coverage:
            record['briefingCoverage'] = coverage[record['id']]
        if record['id'] in debian:
            record['debianPackages'] = debian[record['id']]
    if not records:
        raise SystemExit('No valid CVE snapshot available')
    translation_file = ROOT / 'cve-ko.json'
    translations = json.loads(translation_file.read_text(encoding='utf-8')) if translation_file.exists() else {}
    records = enrich_cves(records, {'cves': old_rows.values()}, translations)
    for item in records:
        apply_official_patches(item, old_rows.get(item['id'], {}), news)
        annotate_review_fields(item)
    lookup = ROOT / 'debian-packages.json'
    lookup_temp = lookup.with_suffix('.tmp')
    lookup_temp.write_text(json.dumps(debian, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    lookup_temp.replace(lookup)
    archive = build_archive(previous_archive, old_rows, nvd, feed, records, kev, debian, news, translations)
    write_archive = ROOT / 'cve-archive.json'
    write_archive_temp = write_archive.with_suffix('.tmp')
    write_archive_temp.write_text(json.dumps(archive, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    write_archive_temp.replace(write_archive)
    blocked = sorted(name for name, status in statuses.items() if status['state'] != 'ok')
    completed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    snapshot = dict(
        updatedAt=NOW.isoformat(), cves=records, news=news, feeds=feeds,
        history=build_history(records, previous), sources=dict(sorted(statuses.items())),
        collection=dict(
            state='complete' if not blocked else 'degraded',
            completedAt=completed_at,
            lastCompleteAt=completed_at if not blocked else (previous.get('collection') or {}).get('lastCompleteAt'),
            blockedSources=blocked,
            runId=os.environ.get('GITHUB_RUN_ID'), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
        ),
    )
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    temp.replace(path)
    print(f'{len(records)} CVEs, {len(news)} linked news items, {sum(bool(article.get("image")) for article in news)} with publisher images')


if __name__ == '__main__':
    collect()
