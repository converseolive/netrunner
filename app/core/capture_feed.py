"""
NetRunner OS - New-capture feed

Checks Malware-Traffic-Analysis.net's dated yearly index for posts newer than a
chosen cut-off and keeps only those whose titles match one of NetRunner's
scenarios. Everything else (phishing kits, mobile exploit kits, file-only
posts...) is dropped, so the list stays relevant.

Refreshing only reads index pages: nothing is downloaded until the user clicks
Fetch & analyze on an entry. At that point the post's own page is read and the
capture link is taken from it, and only a capture file in that post's own
folder on the same site is accepted.

Discovered entries are held in memory by id, so the fetch route can keep
accepting ids only (never a client-supplied URL).
"""

import datetime
import html
import re
import urllib.parse
import urllib.request

from app.core.detection_match import SCENARIOS

BASE = 'https://www.malware-traffic-analysis.net/'
TIMEOUT = 15
MAX_PAGE_BYTES = 2 * 1024 ** 2
USER_AGENT = 'NetRunner/1.0 (lab capture listing)'

# How far back a refresh can look, in days.
RANGES = {30: 'Last 30 days', 90: 'Last 90 days', 365: 'Last year'}
DEFAULT_RANGE = 90

# Title keywords -> scenario. A post is kept only if at least one rule matches.
RULES = [
    ('port_scan', r'\bscans?\b|\bscanning\b|\bprobes?\b'),
    ('dga', r'\bDGA\b|domain generation'),
    ('dns_exfil', r'DNS tunnel|DNS exfil'),
    ('http_exfil', r'stealer|\bStealC\b|\bLumma\b|exfil|data theft|infostealer'),
    ('c2_beacon', r'\bRAT\b|Cobalt Strike|\bC2\b|beacon|backdoor|botnet|\bSliver\b|'
                  r'Brute Ratel|\bHavoc\b|NetSupport|Remcos|XWorm|AsyncRAT|'
                  r'ScreenConnect|MeshAgent|\bQakBot\b|\bIcedID\b|Emotet|Trickbot'),
    ('lateral_movement', r'lateral|PsExec|\bWinRM\b|spreads? to'),
    ('kerberoast', r'kerberoast'),
    ('dcsync', r'DCSync|domain controller|Active Directory|\bAD environment\b'),
    ('ntlm_relay', r'\bNTLM\b'),
]
_RULES = [(s, re.compile(p, re.I)) for s, p in RULES]

_ITEM = re.compile(
    r'<li>\s*<a href="(?P<path>\d{2}/\d{2}/index\d*\.html)"[^>]*>(?P<date>\d{4}-\d{2}-\d{2})</a>'
    r'\s*--\s*<a [^>]*>(?P<title>.*?)</a>', re.I | re.S)
_POST_PATH = re.compile(r'^\d{4}/\d{2}/\d{2}/index\d*\.html$')
_CAPTURE_LINK = re.compile(r'href="([^"/]+\.(?:pcap|pcapng|cap)(?:\.zip)?)"', re.I)

# id -> entry, for everything a refresh has listed.
_discovered = {}


class FeedError(Exception):
    """A refresh or link lookup failed in a way worth showing the user."""


def _get(url, opener=None):
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with opener(req, timeout=TIMEOUT) as resp:
            data = resp.read(MAX_PAGE_BYTES + 1)
    except OSError as e:
        raise FeedError(f'Could not reach {urllib.parse.urlsplit(url).netloc}: '
                        f'{getattr(e, "reason", None) or e}') from None
    if len(data) > MAX_PAGE_BYTES:
        raise FeedError('The listing page was unexpectedly large.')
    return data.decode('utf-8', 'replace')


def classify(title):
    """Scenarios a post title matches, in rule order (empty = not relevant)."""
    return [s for s, rx in _RULES if rx.search(title)]


def parse_index(page, year):
    """Posts listed on one year's index page."""
    out = []
    for m in _ITEM.finditer(page):
        title = html.unescape(re.sub(r'<[^>]+>', '', m.group('title'))).strip()
        out.append({'date': m.group('date'), 'title': title,
                    'page_url': f'{BASE}{year}/{m.group("path")}'})
    return out


def _entry(post, scenarios, n):
    techs = [SCENARIOS[s][2] for s in scenarios if s in SCENARIOS and SCENARIOS[s][2]]
    return {
        'id': f'mta-new-{post["date"]}' + (f'-{n}' if n else ''),
        'title': post['title'],
        'date': post['date'],
        'source': 'mta',
        'page_url': post['page_url'],
        'file_url': None,              # looked up from the post when fetched
        'size': 'size on source page',
        'format': 'zip (password)',
        'scenarios': scenarios,
        'techniques': list(dict.fromkeys(techs)),
        'summary': f'Posted {post["date"]}. Matched on its title.',
        'notes': '',
        'discovered': True,
    }


def scan(days=DEFAULT_RANGE, opener=None, today=None, known_pages=()):
    """List relevant posts from the last `days` days, newest first."""
    if days not in RANGES:
        raise FeedError('Unsupported time range.')
    today = today or datetime.date.today()
    cutoff = today - datetime.timedelta(days=days)
    known = set(known_pages)

    posts = []
    for year in range(today.year, cutoff.year - 1, -1):
        posts.extend(parse_index(_get(f'{BASE}{year}/index.html', opener), year))

    found, per_day, skipped = [], {}, 0
    for post in sorted(posts, key=lambda p: p['date'], reverse=True):
        if post['date'] < cutoff.isoformat() or post['page_url'] in known:
            continue
        scenarios = classify(post['title'])
        if not scenarios:
            skipped += 1
            continue
        n = per_day.get(post['date'], 0)
        per_day[post['date']] = n + 1
        e = _entry(post, scenarios, n)
        _discovered[e['id']] = e
        found.append(e)
    return {'captures': found, 'skipped': skipped, 'days': days,
            'since': cutoff.isoformat()}


def discovered(entry_id):
    return _discovered.get(entry_id)


def resolve_file_url(entry, opener=None):
    """The capture link on a discovered post's page, restricted to that post's
    own folder on the same site."""
    page_url = entry.get('page_url', '')
    if not page_url.startswith(BASE) or not _POST_PATH.match(page_url[len(BASE):]):
        raise FeedError('This entry does not point at a Malware-Traffic-Analysis post.')
    links = _CAPTURE_LINK.findall(_get(page_url, opener))
    if not links:
        raise FeedError('No capture file is linked from that post. Open the source page.')
    name = links[0]
    if '..' in name or name.startswith(('.', '/')):
        raise FeedError('The post links its capture somewhere unexpected.')
    return urllib.parse.urljoin(page_url, name)
