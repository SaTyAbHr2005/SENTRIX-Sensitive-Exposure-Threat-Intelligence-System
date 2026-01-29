from flask import current_app, jsonify
from . import health_bp
from ...extensions import mongo

@health_bp.route("/health", methods=["GET"])
def health():
    # quick mongo ping
    try:
        # using flask-pymongo's cx
        client = mongo.cx
        client.admin.command("ping")
        mongo_ok = True
    except Exception as e:
        mongo_ok = False

    return jsonify({
        "service": "sentrix-v2",
        "mongo": mongo_ok
    })
