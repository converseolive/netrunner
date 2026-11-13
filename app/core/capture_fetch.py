"""
NetRunner OS - Fetch a recommended capture into the library

Downloads a catalog entry's file on the server, unpacks it if it is a zip
(including password-protected zips), and saves the capture(s) into the library
so they can be analyzed and replayed straight away.

Only URLs from the curated catalog can be fetched: the client sends a catalog
id, never a URL, so this cannot be pointed at arbitrary hosts. Downloads and
extraction are size-capped, and zip members are written by basename only.
"""

import os
import re
import shutil
import tempfile
import time
import urllib.request
import zipfile

from werkzeug.utils import secure_filename

from app.core import capture_catalog, capture_feed
from app.core.engine import active_task_status, log_message
from app.core.playlist import is_capture_name

try:  # optional: opens AES-encrypted zips that the standard library cannot
    import pyzipper
except ImportError:  # pragma: no cover - depends on the environment
    pyzipper = None

MAX_DOWNLOAD_BYTES = 1024 ** 3          # 1 GiB
MAX_EXTRACT_BYTES = 2 * 1024 ** 3       # 2 GiB of capture data per zip
CHUNK = 256 * 1024
TIMEOUT = 60
USER_AGENT = 'NetRunner/1.0 (lab capture fetch)'

AES_COMPRESS_TYPE = 99


class FetchError(Exception):
    """A fetch failed in a way worth showing the user verbatim."""


def fetchable(entry):
    """True if the entry points at a single file the app can download."""
    return entry.get('format') != 'pcap set'


def find_entry(entry_id):
    """A curated entry, or one a feed refresh listed this session."""
    for e in capture_catalog.CATALOG:
        if e['id'] == entry_id:
            return e
    return capture_feed.discovered(entry_id) if entry_id else None


def candidate_passwords(entry, password=None):
    """Passwords to try, most likely first."""
    out = []
    if password:
        out.append(password)
    out.append('infected')
    # Malware-Traffic-Analysis has also used date-stamped passwords; try the
    # post's date as a fallback (from its URL, e.g. .../2024/04/18/...).
    m = re.search(r'/(\d{4})/(\d{2})/(\d{2})/', entry.get('page_url', ''))
    if m:
        out.append('infected_' + ''.join(m.groups()))
    return list(dict.fromkeys(out))


def _should_stop():
    return not active_task_status.get('is_running', True)


def download(url, dest, opener=None):
    """Stream `url` to `dest`, updating job progress. Returns bytes written."""
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with opener(req, timeout=TIMEOUT) as resp:
        try:
            total = int(resp.headers.get('Content-Length') or 0)
        except (TypeError, ValueError):
            total = 0
        if total > MAX_DOWNLOAD_BYTES:
            raise FetchError(f'File is {total // 1024 ** 2} MB, over the '
                             f'{MAX_DOWNLOAD_BYTES // 1024 ** 2} MB download limit.')
        active_task_status['total'] = total
        written = 0
        last_log = 0
        with open(dest, 'wb') as out:
            while True:
                if _should_stop():
                    raise FetchError('Stopped.')
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise FetchError('Download exceeded the size limit.')
                out.write(chunk)
                active_task_status['progress'] = written
                mb = written // 1024 ** 2
                active_task_status['message'] = (
                    f'Downloading… {mb} MB' + (f' of {total // 1024 ** 2} MB' if total else ''))
                if mb - last_log >= 25:
                    last_log = mb
                    log_message(f'[*] {mb} MB downloaded')
    if not written:
        raise FetchError('The server returned an empty file.')
    return written


def _open_zip(path):
    if pyzipper is not None:
        return pyzipper.AESZipFile(path)
    return zipfile.ZipFile(path)


def _copy_member(zf, info, dest, pwd):
    """Extract one member to `dest`, bounded by its declared size."""
    limit = info.file_size
    written = 0
    with zf.open(info, pwd=pwd) as src, open(dest, 'wb') as out:
        while True:
            if _should_stop():
                raise FetchError('Stopped.')
            chunk = src.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > limit:
                raise FetchError(f'{info.filename} is larger than its zip header says.')
            out.write(chunk)


def extract_zip(path, folder, passwords):
    """Save every capture inside the zip at `path` into `folder`. Returns names."""
    try:
        zf = _open_zip(path)
    except zipfile.BadZipFile:
        raise FetchError('The download is not a valid zip file.') from None
    with zf:
        members = [m for m in zf.infolist()
                   if not m.is_dir() and is_capture_name(os.path.basename(m.filename))
                   and not os.path.basename(m.filename).startswith('.')]
        if not members:
            raise FetchError('The zip does not contain a capture file '
                             '(.pcap, .pcapng, .cap, .gz).')
        if sum(m.file_size for m in members) > MAX_EXTRACT_BYTES:
            raise FetchError('The zip expands past the extraction limit.')
        if pyzipper is None and any(m.compress_type == AES_COMPRESS_TYPE for m in members):
            raise FetchError('This zip uses AES encryption. Run "pip install pyzipper" '
                             'and restart NetRunner, or extract it with 7-Zip and use '
                             'Add captures.')

        encrypted = any(m.flag_bits & 0x1 for m in members)
        tries = [p.encode() for p in passwords] if encrypted else [None]
        for pwd in tries:
            saved = []
            try:
                for m in members:
                    name = secure_filename(os.path.basename(m.filename))
                    if not is_capture_name(name):
                        continue
                    _copy_member(zf, m, os.path.join(folder, name), pwd)
                    saved.append(name)
                if encrypted:
                    log_message('[+] Zip password accepted')
                return saved
            except (RuntimeError, zipfile.BadZipFile) as e:
                # wrong password ("Bad password" / bad CRC) - clean up and try the next
                for name in saved:
                    _remove(os.path.join(folder, name))
                if not encrypted:
                    raise FetchError(f'Could not extract the zip: {e}') from None
        raise FetchError('Zip password not accepted. Enter the password from the '
                         "source's site and try again.")


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def fetch_into_library(entry, folder, password=None, opener=None):
    """Download `entry` into `folder`. Returns the saved capture names."""
    if not fetchable(entry):
        raise FetchError('This source is a set of files: download it from the source page.')
    os.makedirs(folder, exist_ok=True)
    url = entry.get('file_url')
    if not url:
        # A feed entry: read its post to find the capture link.
        active_task_status['message'] = 'Finding the capture on the source page…'
        try:
            url = capture_feed.resolve_file_url(entry, opener=opener)
        except capture_feed.FeedError as e:
            raise FetchError(str(e)) from None
    log_message(f'[*] Fetching {url}')
    tmpdir = tempfile.mkdtemp(prefix='.fetch-', dir=folder)
    try:
        tmp = os.path.join(tmpdir, 'download')
        size = download(url, tmp, opener=opener)
        log_message(f'[+] Downloaded {size / 1024 ** 2:.1f} MB')

        if zipfile.is_zipfile(tmp):
            active_task_status['message'] = 'Extracting…'
            saved = extract_zip(tmp, folder, candidate_passwords(entry, password))
        else:
            name = secure_filename(os.path.basename(url.split('?')[0]))
            if not is_capture_name(name):
                raise FetchError('The download is not a capture file or a zip.')
            shutil.move(tmp, os.path.join(folder, name))
            saved = [name]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if not saved:
        raise FetchError('No capture files were saved.')
    log_message(f'[+] Saved to library: {", ".join(saved)}')
    return saved


def run_fetch(entry, folder, password=None, opener=None):
    """Job body: fetch, record the result on the job, report errors plainly."""
    active_task_status['message'] = 'Connecting…'
    started = time.time()
    try:
        saved = fetch_into_library(entry, folder, password, opener=opener)
    except FetchError as e:
        active_task_status['error'] = str(e)
        active_task_status['message'] = f'Failed: {e}'
        log_message(f'[!!!] {e}')
        return
    except OSError as e:  # network / TLS / disk
        msg = f'Download failed: {getattr(e, "reason", None) or e}'
        active_task_status['error'] = msg
        active_task_status['message'] = msg
        log_message(f'[!!!] {msg}')
        return
    active_task_status['result'] = {'saved': saved}
    active_task_status['message'] = (f'Saved {len(saved)} capture(s) in '
                                     f'{time.time() - started:.0f}s')
