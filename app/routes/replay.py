"""
NetRunner OS - Replay Routes
"""

import os
from flask import Blueprint, request, jsonify, current_app
from app.core.engine import (replay_pcap_task, register_run, run_job,
                             stop_all_jobs, running_job_count, MAX_CONCURRENT_JOBS)
from app.core.interfaces import validate_interface

bp = Blueprint('replay', __name__)


@bp.route('/replay/start', methods=['POST'])
def start_replay():
    """Start replaying a PCAP file with optional rewrite rules."""
    if running_job_count() >= MAX_CONCURRENT_JOBS:
        return jsonify({'error': 'Too many jobs running. Stop one and retry.'}), 400

    try:
        data = request.get_json()
        filepath = data.get('filepath') or current_app.config.get('LAST_PCAP')
        if not filepath:
            return jsonify({'error': 'No PCAP file loaded. Please upload one first.'}), 400

        if not os.path.exists(filepath):
            return jsonify({'error': 'PCAP file not found.'}), 400

        ok, err = validate_interface(data.get('interface', 'eth0'))
        if not ok:
            return jsonify({'error': err}), 400

        ip_map = data.get('ip_map', {})
        params = {
            'filepath': filepath,
            'interface': data.get('interface', 'eth0'),
            'replay_speed': data.get('speed', 'original'),
            'loop_replay': data.get('loop', False),
            'loop_count': int(data.get('loop_count', 0)),
            'ttl': int(data['ttl']) if data.get('ttl') else None,
            'vlan_id': int(data['vlan_id']) if data.get('vlan_id') else None,
            'ip_map': ip_map,
            'mac_map': data.get('mac_map', {}),
            'port_map': data.get('port_map', {})
        }

        # Record the run so the ExtraHop detection loop can correlate it. The IPs
        # on the wire are the rewrite targets plus any original IPs left untouched.
        wire_ips = list(ip_map.values())
        for ip in (data.get('participant_ips') or []):
            if ip and ip not in ip_map:  # not rewritten -> original IP stays on the wire
                wire_ips.append(ip)
        register_run({
            'kind': 'replay',
            'scenario': None,
            'label': f"Replay: {os.path.basename(filepath)}",
            'ips': wire_ips,
            'interface': params['interface'],
        })

        jid = run_job('replay', replay_pcap_task, (params,),
                      label=f"Replay: {os.path.basename(filepath)}")
        return jsonify({'status': 'Replay started.', 'job_id': jid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/replay/stop', methods=['POST'])
def stop_replay():
    """Stop all running jobs (back-compat 'stop everything')."""
    stop_all_jobs()
    return jsonify({'status': 'Stop signal sent to all jobs.'})
