"""
NetRunner OS - System / host info routes
"""

from flask import Blueprint, jsonify
from app.core.interfaces import list_interfaces

bp = Blueprint('system', __name__)


@bp.route('/interfaces', methods=['GET'])
def interfaces():
    return jsonify({'interfaces': list_interfaces()})
