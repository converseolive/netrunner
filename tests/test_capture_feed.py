"""Tests for the new-capture feed (no network: pages are served by a fake opener)."""

import datetime
import io
import shutil
import tempfile
import unittest
from unittest import mock

from app import create_app
from app.core import capture_feed, capture_fetch
from app.core.engine import bind_job, new_job, get_job

INDEX_2026 = """
<LI><a href="10/22/index.html" class="list_header">2026-10-22</a> -- <a href="10/22/index.html" class="main_menu">Seven days of scans and probes hitting my web server</a></LI>
<LI><a href="10/16/index.html" class="list_header">2026-10-16</a> -- <a href="10/16/index.html" class="main_menu">Coruna-like iOS exploit kit traffic</a></LI>
<LI><a href="10/02/index.html" class="list_header">2026-10-02</a> -- <a href="10/02/index.html" class="main_menu">AMOS Stealer infection</a></LI>
<LI><a href="10/02/index2.html" class="list_header">2026-10-02</a> -- <a href="10/02/index2.html" class="main_menu">SmartApeSG ClickFix --&gt; NetSupport RAT</a></LI>
<LI><a href="01/05/index.html" class="list_header">2026-01-05</a> -- <a href="01/05/index.html" class="main_menu">XWorm infection</a></LI>
"""
INDEX_2025 = """
<LI><a href="12/20/index.html" class="list_header">2025-12-20</a> -- <a href="12/20/index.html" class="main_menu">Remcos RAT infection</a></LI>
"""
POST = '<a href="2026-10-02-notes.txt.zip">notes</a> <a href="2026-10-02-RAT-traffic.pcap.zip">pcap</a>'

TODAY = datetime.date(2026, 11, 13)


class _Resp(io.BytesIO):
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _site(pages):
    seen = []

    def opener(req, timeout=None):
        seen.append(req.full_url)
        for suffix, body in pages.items():
            if req.full_url.endswith(suffix):
                return _Resp(body.encode() if isinstance(body, str) else body)
        raise OSError('404')
    opener.seen = seen
    return opener


SITE = {'2026/index.html': INDEX_2026, '2025/index.html': INDEX_2025}


class ClassifyTests(unittest.TestCase):
    def test_relevant_titles_map_to_scenarios(self):
        self.assertEqual(capture_feed.classify('XWorm infection'), ['c2_beacon'])
        self.assertEqual(capture_feed.classify('Lumma Stealer or variant'), ['http_exfil'])
        self.assertEqual(capture_feed.classify('Seven days of scans and probes'), ['port_scan'])

    def test_unrelated_titles_are_dropped(self):
        self.assertEqual(capture_feed.classify('Coruna-like iOS exploit kit traffic'), [])
        self.assertEqual(capture_feed.classify('Files for an ISC Diary'), [])


class ScanTests(unittest.TestCase):
    def test_filters_by_range_and_relevance(self):
        res = capture_feed.scan(90, opener=_site(SITE), today=TODAY)
        titles = [e['title'] for e in res['captures']]
        self.assertEqual(titles, ['Seven days of scans and probes hitting my web server',
                                  'AMOS Stealer infection',
                                  'SmartApeSG ClickFix --> NetSupport RAT'])
        self.assertEqual(res['skipped'], 1)               # the iOS exploit kit
        ids = [e['id'] for e in res['captures']]
        self.assertEqual(len(set(ids)), len(ids))         # two posts on one day stay distinct

    def test_year_range_reads_previous_year(self):
        site = _site(SITE)
        res = capture_feed.scan(365, opener=site, today=TODAY)
        self.assertIn('Remcos RAT infection', [e['title'] for e in res['captures']])
        self.assertEqual(len(site.seen), 2)

    def test_short_range_reads_one_index_only(self):
        site = _site(SITE)
        capture_feed.scan(30, opener=site, today=TODAY)
        self.assertEqual(site.seen, [capture_feed.BASE + '2026/index.html'])

    def test_curated_posts_not_repeated(self):
        known = [capture_feed.BASE + '2026/10/02/index.html']
        res = capture_feed.scan(90, opener=_site(SITE), today=TODAY, known_pages=known)
        self.assertNotIn('AMOS Stealer infection', [e['title'] for e in res['captures']])

    def test_unsupported_range_rejected(self):
        with self.assertRaises(capture_feed.FeedError):
            capture_feed.scan(7, opener=_site(SITE), today=TODAY)

    def test_network_failure_is_a_feed_error(self):
        with self.assertRaises(capture_feed.FeedError):
            capture_feed.scan(30, opener=_site({}), today=TODAY)


class ResolveTests(unittest.TestCase):
    def entry(self, url=capture_feed.BASE + '2026/10/02/index.html'):
        return {'page_url': url}

    def test_picks_capture_in_post_folder(self):
        url = capture_feed.resolve_file_url(self.entry(), _site({'index.html': POST}))
        self.assertEqual(url, capture_feed.BASE + '2026/10/02/2026-10-02-RAT-traffic.pcap.zip')

    def test_rejects_other_hosts(self):
        with self.assertRaises(capture_feed.FeedError):
            capture_feed.resolve_file_url(self.entry('https://evil.test/2026/10/02/index.html'),
                                          _site({'index.html': POST}))

    def test_ignores_links_outside_the_post_folder(self):
        page = '<a href="../../../other.pcap.zip">x</a> <a href="https://evil.test/a.pcap">y</a>'
        with self.assertRaises(capture_feed.FeedError):
            capture_feed.resolve_file_url(self.entry(), _site({'index.html': page}))


class FetchDiscoveredTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.jid = new_job('fetch', 'test')
        bind_job(self.jid)

    def tearDown(self):
        get_job(self.jid)['is_running'] = False
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_discovered_entry_is_found_and_fetched_from_its_post(self):
        res = capture_feed.scan(90, opener=_site(SITE), today=TODAY)
        entry = capture_fetch.find_entry(res['captures'][-1]['id'])
        self.assertIsNotNone(entry)
        from tests.test_capture_fetch import _pcap_bytes
        site = _site({'10/02/index2.html': POST, '.pcap.zip': _zip_with(_pcap_bytes())})
        saved = capture_fetch.fetch_into_library(entry, self.dir, opener=site)
        self.assertEqual(saved, ['inner.pcap'])
        self.assertTrue(site.seen[-1].endswith('2026/10/02/2026-10-02-RAT-traffic.pcap.zip'))


def _zip_with(data):
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('inner.pcap', data)
    return buf.getvalue()


class FeedRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_bad_range_400(self):
        self.assertEqual(self.client.get('/captures/feed?days=7').status_code, 400)
        self.assertEqual(self.client.get('/captures/feed?days=x').status_code, 400)

    def test_lists_with_source_details(self):
        with mock.patch.object(capture_feed.urllib.request, 'urlopen', _site(SITE)):
            r = self.client.get('/captures/feed?days=365')
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        e = data['captures'][0]
        self.assertTrue(e['discovered'] and e['fetchable'])
        self.assertEqual(e['source_info']['name'], 'Malware-Traffic-Analysis.net')

    def test_source_unreachable_502(self):
        with mock.patch.object(capture_feed.urllib.request, 'urlopen', _site({})):
            self.assertEqual(self.client.get('/captures/feed?days=30').status_code, 502)


if __name__ == '__main__':
    unittest.main()
