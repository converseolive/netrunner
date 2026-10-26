"""
NetRunner OS - System / host info and job control routes
"""

from flask import Blueprint, jsonify
from app.core.interfaces import list_interfaces
from app.core.engine import list_jobs, stop_job, stop_all_jobs, clear_finished_jobs

bp = Blueprint('system', __name__)


@bp.route('/interfaces', methods=['GET'])
def interfaces():
    return jsonify({'interfaces': list_interfaces()})


@bp.route('/jobs', methods=['GET'])
def jobs():
    return jsonify({'jobs': list_jobs()})


@bp.route('/jobs/<job_id>/stop', methods=['POST'])
def stop_one_job(job_id):
    if stop_job(job_id):
        return jsonify({'status': 'stopping', 'job_id': job_id})
    return jsonify({'error': 'Job not found.'}), 404


@bp.route('/jobs/stop-all', methods=['POST'])
def stop_all():
    stop_all_jobs()
    return jsonify({'status': 'stopping all'})


@bp.route('/jobs/clear', methods=['POST'])
def clear_jobs():
    clear_finished_jobs()
    return jsonify({'status': 'cleared'})
