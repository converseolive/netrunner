"""
NetRunner OS - Capture library + Play all routes
"""

import os
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from app.core import playlist, capture_catalog, capture_fetch
from app.core.rewrite_planner import suggest_lab_subnet
from app.core.settings import get_settings
from app.core.interfaces import validate_interface
from app.core.engine import run_job, running_job_count, MAX_CONCURRENT_JOBS

bp = Blueprint('playlist', __name__)


def _folder():
    folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(folder, exist_ok=True)
    return folder


# ── Library ───────────────────────────────────────────────────────────────────

@bp.route('/captures', methods=['GET'])
def list_captures():
    return jsonify({'captures': playlist.list_captures(_folder())})


@bp.route('/captures/catalog', methods=['GET'])
def recommended_captures():
    return jsonify({'captures': capture_catalog.catalog(),
                    'coverage': capture_catalog.coverage(),
                    'sources': capture_catalog.SOURCES})


@bp.route('/captures/fetch', methods=['POST'])
def fetch_capture():
    """Download a recommended capture into the library as a background job."""
    data = request.get_json() or {}
    entry = capture_fetch.find_entry(data.get('id'))
    if not entry:
        return jsonify({'error': 'Unknown catalog entry.'}), 404
    if not capture_fetch.fetchable(entry):
        return jsonify({'error': 'This source is a set of files: download it from '
                                 'the source page.'}), 400
    if running_job_count() >= MAX_CONCURRENT_JOBS:
        return jsonify({'error': 'Too many jobs running. Stop one and retry.'}), 400
    password = (data.get('password') or '').strip() or None
    jid = run_job('fetch', capture_fetch.run_fetch, (entry, _folder(), password),
                  label=f"Fetch: {entry['title']}")
    return jsonify({'status': 'Fetching.', 'job_id': jid})


@bp.route('/captures', methods=['POST'])
def upload_captures():
    """Save one or more captures to the library without analyzing them."""
    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'No files provided.'}), 400
    saved, skipped = [], []
    for f in files:
        name = secure_filename(f.filename or '')
        if not playlist.is_capture_name(name):
            skipped.append(f.filename)
            continue
        f.save(os.path.join(_folder(), name))
        saved.append(name)
    if not saved:
        return jsonify({'error': 'No capture files found (.pcap, .pcapng, .cap, .gz).',
                        'skipped': skipped}), 400
    return jsonify({'saved': saved, 'skipped': skipped})


@bp.route('/captures/<name>', methods=['DELETE'])
def delete_capture(name):
    path = playlist.resolve_capture(_folder(), name)
    if not path:
        return jsonify({'error': 'Capture not found.'}), 404
    os.remove(path)
    return jsonify({'status': 'deleted'})


# ── Play all ──────────────────────────────────────────────────────────────────

def _prepare(data):
    """Resolve, parse and plan the selected captures. Returns (result, error)."""
    names = data.get('captures') or []
    if not names:
        return None, (jsonify({'error': 'Pick at least one capture.'}), 400)

    entries = []
    for name in names:
        path = playlist.resolve_capture(_folder(), name)
        if not path:
            return None, (jsonify({'error': f'Capture not found: {name}'}), 400)
        try:
            hosts = playlist.capture_hosts(path)
        except Exception as e:  # noqa: BLE001 - unreadable/corrupt capture
            return None, (jsonify({'error': f'Could not read {name}: {e}'}), 400)
        entries.append({'name': name, 'path': path, 'hosts': hosts})

    internal = get_settings().get('extrahop', {}).get('internal_networks', [])
    lab = (data.get('lab_subnet') or '').strip()
    if not lab:
        blocks = sum(playlist.internal_block_count(e['hosts']) for e in entries)
        lab = suggest_lab_subnet({'subnets': [None] * max(1, blocks)}, internal) or ''
    if not lab:
        return None, (jsonify({'error': 'lab_subnet is required (e.g. 10.99.0.0/16), '
                               'or configure ExtraHop internal networks in Settings.'}), 400)

    plans = playlist.build_playlist_plan(entries, lab, internal)
    return {'lab_subnet': lab, 'plans': plans}, None


def _public(plans):
    return [{k: v for k, v in p.items() if k != 'path'} for p in plans]


@bp.route('/playlist/preview', methods=['POST'])
def preview_playlist():
    result, err = _prepare(request.get_json() or {})
    if err:
        return err
    return jsonify({'lab_subnet': result['lab_subnet'], 'plans': _public(result['plans'])})


@bp.route('/playlist/play', methods=['POST'])
def play_playlist():
    if running_job_count() >= MAX_CONCURRENT_JOBS:
        return jsonify({'error': 'Too many jobs running. Stop one and retry.'}), 400
    data = request.get_json() or {}
    interface = data.get('interface', 'eth0')
    ok, msg = validate_interface(interface)
    if not ok:
        return jsonify({'error': msg}), 400

    result, err = _prepare(data)
    if err:
        return err

    def _num(key):
        try:
            v = float(data.get(key) or 0)
        except (TypeError, ValueError):
            return None
        return v if v > 0 else None

    options = {
        'interface': interface,
        'speed': data.get('speed', 'original'),
        'gap_seconds': _num('gap_seconds') or 0,
        'max_seconds': _num('max_seconds'),
        'ttl': int(data['ttl']) if data.get('ttl') else None,
        'vlan_id': int(data['vlan_id']) if data.get('vlan_id') else None,
    }
    plans = result['plans']
    jid = run_job('replay', playlist.run_playlist, (plans, options),
                  label=f"Play all ({len(plans)} captures)")
    return jsonify({'status': 'Play all started.', 'job_id': jid,
                    'lab_subnet': result['lab_subnet'], 'plans': _public(plans)})
