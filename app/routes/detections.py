"""
NetRunner OS - ExtraHop Detection Loop Routes

Close the generate -> detect loop: after traffic has been generated, these
endpoints ask the ExtraHop appliance which detections fired and correlate them
back to the scenarios NetRunner ran. The orchestration lives in
app.core.validation so the CLI can reuse it.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, Response

from app.core import extrahop, report, validation
from app.core.engine import clear_runs
from app.core.settings import get_settings

bp = Blueprint('detections', __name__)


@bp.route('/runs', methods=['GET'])
def list_runs():
    return jsonify({'runs': validation.checkable_runs()})


@bp.route('/runs', methods=['DELETE'])
def clear_run_history():
    clear_runs()
    return jsonify({'status': 'cleared'})


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
    """Correlate ExtraHop detections against the scenarios NetRunner ran."""
    return jsonify(validation.run_validation())


@bp.route('/detections/report', methods=['GET'])
def detection_report():
    """Download a standalone HTML detection-validation report."""
    html = report.build_report_html(validation.run_validation())
    stamp = datetime.now().strftime('%Y%m%d-%H%M')
    return Response(html, mimetype='text/html', headers={
        'Content-Disposition': f'attachment; filename="netrunner-detection-report-{stamp}.html"'
    })
