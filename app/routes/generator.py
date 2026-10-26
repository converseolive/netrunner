"""
NetRunner OS - Traffic Generator Routes
"""

from flask import Blueprint, request, jsonify
from app.core.engine import register_run, run_job, running_job_count, MAX_CONCURRENT_JOBS
from app.core.generators import protocol, adversary
from app.core import campaign
from app.core.interfaces import validate_interface

bp = Blueprint('generator', __name__)


def _at_capacity():
    if running_job_count() >= MAX_CONCURRENT_JOBS:
        return jsonify({'error': 'Too many jobs running. Stop one and retry.'}), 400
    return None


@bp.route('/generate/protocol', methods=['POST'])
def generate_protocol():
    """Generate realistic protocol traffic."""
    cap = _at_capacity()
    if cap:
        return cap
    try:
        data = request.get_json()
        proto = data.get('protocol', 'dns')
        interface = data.get('interface', 'eth0')

        ok, err = validate_interface(interface)
        if not ok:
            return jsonify({'error': err}), 400

        params = {
            'interface': interface,
            'protocol': proto,
            'src_ip': data.get('src_ip', '10.0.0.100'),
            'dst_ip': data.get('dst_ip', '10.0.0.1'),
            'src_mac': data.get('src_mac'),
            'dst_mac': data.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(data.get('count', 10)),
            'delay': float(data.get('delay', 0.5)),
            'domain': data.get('domain', 'example.com'),
            'payload': data.get('payload', ''),
            'ipjitter': float(data.get('ipjitter', 0) or 0),
        }

        jid = run_job('generate', protocol.generate, (params,),
                      label=f'{proto.upper()} traffic')
        return jsonify({'status': f'{proto.upper()} generation started.', 'job_id': jid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/generate/adversary', methods=['POST'])
def generate_adversary():
    """Generate adversary simulation traffic."""
    cap = _at_capacity()
    if cap:
        return cap
    try:
        data = request.get_json()
        sim_type = data.get('simulation', 'c2_beacon')
        interface = data.get('interface', 'eth0')

        ok, err = validate_interface(interface)
        if not ok:
            return jsonify({'error': err}), 400

        params = {
            'interface': interface,
            'simulation': sim_type,
            'src_ip': data.get('src_ip', '10.0.0.100'),
            'dst_ip': data.get('dst_ip', '10.0.0.1'),
            'c2_host': data.get('c2_host', '185.100.87.42'),
            'src_mac': data.get('src_mac'),
            'dst_mac': data.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(data.get('count', 50)),
            'delay': float(data.get('delay', 1.0)),
            'domain': data.get('domain', 'evil-c2.xyz'),
            'duration': int(data.get('duration', 60)),
            'duration_min': float(data.get('duration_min', 0) or 0),
            'jitter': float(data.get('jitter', 0) or 0),
            'ipjitter': float(data.get('ipjitter', 0) or 0),
        }

        # Record the run so the ExtraHop detection loop can correlate it later.
        register_run({
            'scenario': sim_type,
            'kind': 'adversary',
            'adversary_ip': params['src_ip'],
            'victim_ip': params['dst_ip'],
            'c2_ip': params['c2_host'],
            'interface': interface,
        })

        jid = run_job('generate', adversary.generate, (params,), label=sim_type)
        return jsonify({'status': f'{sim_type} simulation started.', 'job_id': jid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/generate/campaign', methods=['POST'])
def generate_campaign():
    """Run the full adversary suite (or a subset) sequentially."""
    cap = _at_capacity()
    if cap:
        return cap
    try:
        data = request.get_json() or {}
        ok, err = validate_interface(data.get('interface', 'eth0'))
        if not ok:
            return jsonify({'error': err}), 400
        settings = {
            'interface': data.get('interface', 'eth0'),
            'src_ip': data.get('src_ip', '10.0.0.100'),
            'dst_ip': data.get('dst_ip', '10.0.0.1'),
            'c2_host': data.get('c2_host', '185.100.87.42'),
            'src_mac': data.get('src_mac'),
            'dst_mac': data.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(data.get('count', 30)),
            'delay': float(data.get('delay', 0.1)),
            'domain': data.get('domain', 'evil-c2.xyz'),
            'ipjitter': float(data.get('ipjitter', 0) or 0),
        }
        scenarios = data.get('scenarios')
        planned = len(campaign.campaign_plan(settings, scenarios))

        jid = run_job('generate', campaign.run_campaign, (settings, scenarios),
                      label=f'Adversary suite ({planned})')
        return jsonify({'status': 'Adversary campaign started.',
                        'scenarios': planned, 'job_id': jid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
