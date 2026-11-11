"""Tests for fetching recommended captures into the library (no network used)."""

import io
import os
import shutil
import tempfile
import time
import unittest
import zipfile
from unittest import mock

from scapy.all import Ether, IP, TCP, wrpcap

from app import create_app
from app.core import capture_fetch, engine
from app.core.engine import bind_job, new_job, get_job


def _pcap_bytes():
    path = tempfile.mktemp(suffix='.pcap')
    wrpcap(path, [Ether() / IP(src='10.1.1.5', dst='8.8.8.8') / TCP(dport=80)] * 3)
    with open(path, 'rb') as f:
        data = f.read()
    os.remove(path)
    return data


class _Resp(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.headers = {'Content-Length': str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _opener(data):
    seen = []

    def opener(req, timeout=None):
        seen.append(req.full_url)
        return _Resp(data)
    opener.seen = seen
    return opener


def _zip(members, password=None):
    """Build a zip in memory. ZipCrypto passwords need the zip CLI, so encrypted
    zips are built with the `zip` tool when available."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


ENTRY = {'id': 't', 'title': 'Test', 'format': 'zip',
         'page_url': 'https://example.test/2024/04/18/index.html',
         'file_url': 'https://example.test/files/capture.pcap.zip'}


class FetchCoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.jobs = [self._job('test')]
        self.pcap = _pcap_bytes()

    def _job(self, label):
        jid = new_job('fetch', label)
        bind_job(jid)
        return jid

    def tearDown(self):
        for jid in getattr(self, 'jobs', []):
            get_job(jid)['is_running'] = False
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_plain_capture_saved_by_url_name(self):
        entry = dict(ENTRY, format='pcap', file_url='https://example.test/a/neris.pcap')
        saved = capture_fetch.fetch_into_library(entry, self.dir, opener=_opener(self.pcap))
        self.assertEqual(saved, ['neris.pcap'])
        self.assertEqual(open(os.path.join(self.dir, 'neris.pcap'), 'rb').read(), self.pcap)

    def test_zip_extracts_only_captures_by_basename(self):
        data = _zip({'nested/dir/inner.pcap': self.pcap, 'README.txt': b'hi',
                     '../../evil.pcap': self.pcap})
        saved = capture_fetch.fetch_into_library(ENTRY, self.dir, opener=_opener(data))
        self.assertEqual(sorted(saved), ['evil.pcap', 'inner.pcap'])
        # nothing escaped the folder, no temp dirs left behind
        self.assertEqual(sorted(os.listdir(self.dir)), ['evil.pcap', 'inner.pcap'])

    def test_zip_without_capture_fails(self):
        data = _zip({'notes.txt': b'nothing here'})
        with self.assertRaises(capture_fetch.FetchError):
            capture_fetch.fetch_into_library(ENTRY, self.dir, opener=_opener(data))
        self.assertEqual(os.listdir(self.dir), [])

    def test_non_capture_download_rejected(self):
        entry = dict(ENTRY, format='pcap', file_url='https://example.test/page.html')
        with self.assertRaises(capture_fetch.FetchError):
            capture_fetch.fetch_into_library(entry, self.dir, opener=_opener(b'<html>'))

    def test_oversize_download_rejected(self):
        with mock.patch.object(capture_fetch, 'MAX_DOWNLOAD_BYTES', 10):
            with self.assertRaises(capture_fetch.FetchError):
                capture_fetch.fetch_into_library(ENTRY, self.dir, opener=_opener(self.pcap))

    def test_pcap_set_not_fetchable(self):
        with self.assertRaises(capture_fetch.FetchError):
            capture_fetch.fetch_into_library(dict(ENTRY, format='pcap set'), self.dir)

    def test_candidate_passwords(self):
        pw = capture_fetch.candidate_passwords(ENTRY, 'mine')
        self.assertEqual(pw, ['mine', 'infected', 'infected_20240418'])

    @unittest.skipUnless(shutil.which('zip'), 'zip CLI needed to build an encrypted zip')
    def test_password_zip_tries_candidates(self):
        src = tempfile.mkdtemp()
        try:
            with open(os.path.join(src, 'secret.pcap'), 'wb') as f:
                f.write(self.pcap)
            zpath = os.path.join(src, 'x.zip')
            os.system(f'cd "{src}" && zip -q -P infected_20240418 x.zip secret.pcap')
            data = open(zpath, 'rb').read()
        finally:
            shutil.rmtree(src, ignore_errors=True)
        saved = capture_fetch.fetch_into_library(ENTRY, self.dir, opener=_opener(data))
        self.assertEqual(saved, ['secret.pcap'])
        self.assertEqual(open(os.path.join(self.dir, 'secret.pcap'), 'rb').read(), self.pcap)

        # wrong user password and no matching fallback -> clear error, nothing left
        shutil.rmtree(self.dir); os.makedirs(self.dir)
        entry = dict(ENTRY, page_url='https://example.test/x')
        with self.assertRaises(capture_fetch.FetchError):
            capture_fetch.fetch_into_library(entry, self.dir, 'wrong', opener=_opener(data))
        self.assertEqual(os.listdir(self.dir), [])

    def test_run_fetch_records_result_and_errors(self):
        entry = dict(ENTRY, format='pcap', file_url='https://example.test/a/x.pcap')
        capture_fetch.run_fetch(entry, self.dir, opener=_opener(self.pcap))
        self.assertEqual(engine.active_task_status['result'], {'saved': ['x.pcap']})

        self.jobs.append(self._job('test2'))
        capture_fetch.run_fetch(dict(ENTRY, file_url='https://example.test/a/y.html',
                                     format='pcap'), self.dir, opener=_opener(b'x'))
        self.assertTrue(engine.active_task_status['error'])


class FetchRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.dir = tempfile.mkdtemp()
        self.app.config['UPLOAD_FOLDER'] = self.dir
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_unknown_id_rejected(self):
        r = self.client.post('/captures/fetch', json={'id': 'nope'})
        self.assertEqual(r.status_code, 404)

    def test_url_cannot_be_supplied(self):
        # only catalog ids are accepted; a URL in the body is ignored
        r = self.client.post('/captures/fetch', json={'url': 'http://169.254.169.254/'})
        self.assertEqual(r.status_code, 404)

    def test_pcap_set_rejected(self):
        r = self.client.post('/captures/fetch', json={'id': 'netresec-maccdc-2012'})
        self.assertEqual(r.status_code, 400)

    def test_catalog_marks_fetchable(self):
        caps = self.client.get('/captures/catalog').get_json()['captures']
        by_id = {c['id']: c for c in caps}
        self.assertFalse(by_id['netresec-maccdc-2012']['fetchable'])
        self.assertTrue(by_id['ctu13-neris']['fetchable'])

    def test_fetch_job_then_analyze_from_library(self):
        pcap = _pcap_bytes()
        with mock.patch.object(capture_fetch.urllib.request, 'urlopen', _opener(pcap)):
            r = self.client.post('/captures/fetch', json={'id': 'ctu-conficker-90'})
            jid = r.get_json()['job_id']
            for _ in range(50):
                job = self.client.get(f'/jobs/{jid}').get_json()
                if not job['is_running']:
                    break
                time.sleep(0.05)
        self.assertIsNone(job['error'])
        self.assertEqual(job['result'], {'saved': ['192.168.3.104-unvirus.pcap']})

        r = self.client.post('/analyze_pcap', json={'library': '192.168.3.104-unvirus.pcap'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['total_packets'], 3)

    def test_analyze_library_refuses_traversal(self):
        r = self.client.post('/analyze_pcap', json={'library': '../etc/passwd.pcap'})
        self.assertEqual(r.status_code, 404)

    def test_job_lookup_404(self):
        self.assertEqual(self.client.get('/jobs/missing').status_code, 404)


if __name__ == '__main__':
    unittest.main()
