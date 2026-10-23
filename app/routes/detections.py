"""
NetRunner OS - ExtraHop Detection Loop Routes

Closes the generate -> detect loop: after traffic has been generated, these
endpoints ask the ExtraHop appliance which detections fired and correlate them
back to the scenarios NetRunner ran.
"""

import time
from datetime import datetime
from flask import Blueprint, request, jsonify, Response

from app.core import extrahop, detection_match, report
from app.core.engine import recent_runs
from app.core.settings import get_settings

bp = Blueprint('detections', __name__)

_WINDOW_SLACK_MS = 300_000  # widen the detection search 5 min each side of a run


def _checkable_runs():
    """Recorded runs the detection loop can correlate (adversary + replay)."""
    runs = [r for r in recent_runs
            if r.get('scenario') in detection_match.SCENARIOS
            or r.get('kind') == 'replay']
    return list(reversed(runs))


def _run_validation():
    """Shared by the validate and report endpoints."""
    cfg = get_settings().get('extrahop', {})
    runs = _checkable_runs()

    if not extrahop.is_configured(cfg):
        result = detection_match.sample_result()
        result['note'] = 'not_configured'
        return result

    if not runs:
        empty = detection_match.validate([], [])
        empty['note'] = 'no_runs'
        return empty

    now = int(time.time() * 1000)
    starts = [r['start_ms'] for r in runs if r.get('start_ms')]
    from_ms = (min(starts) - _WINDOW_SLACK_MS) if starts else now - 3_600_000
    until_ms = now + _WINDOW_SLACK_MS

    try:
        detections = extrahop.search_detections(cfg, from_ms, until_ms)
    except Exception as e:  # noqa: BLE001 - surface the error, keep the view usable
        result = detection_match.sample_result()
        result['note'] = 'appliance_error'
        result['error'] = str(e)
        return result

    result = detection_match.validate(runs, detections)
    result['detection_total'] = len(detections)
    return result


@bp.route('/runs', methods=['GET'])
def list_runs():
    return jsonify({'runs': _checkable_runs()})


@bp.route('/extrahop/test', methods=['POST'])
def test_extrahop():
    """Test the appliance connection, optionally with not-yet-saved values."""
    cfg = dict(get_settings().get('extrahop', {}))
    override = request.get_json(silent=True) or {}
    for k in ('base_url', 'api_key', 'verify_tls'):
        if override.get(k):
            cfg[k] = override[k]
    return jsonify(extrahop.test_connection(cfg))


@bp.route('/detections/validate', methods=['POST'])
def validate_detections():
    """
    Correlate ExtraHop detections against the scenarios NetRunner ran. Falls back
    to a labelled sample result when no appliance is configured.
    """
    return jsonify(_run_validation())


@bp.route('/detections/report', methods=['GET'])
def detection_report():
    """Download a standalone HTML detection-validation report."""
    result = _run_validation()
    html = report.build_report_html(result)
    stamp = datetime.now().strftime('%Y%m%d-%H%M')
    return Response(html, mimetype='text/html', headers={
        'Content-Disposition': f'attachment; filename="netrunner-detection-report-{stamp}.html"'
    })
