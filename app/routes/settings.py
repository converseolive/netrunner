"""
NetRunner OS - Settings Routes
"""

from flask import Blueprint, request, jsonify
from app.core.settings import save_settings, public_settings

bp = Blueprint('settings', __name__)


@bp.route('/settings', methods=['GET'])
def read_settings():
    return jsonify(public_settings())


@bp.route('/settings', methods=['POST'])
def write_settings():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided.'}), 400
    try:
        save_settings(data)
        return jsonify(public_settings())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
