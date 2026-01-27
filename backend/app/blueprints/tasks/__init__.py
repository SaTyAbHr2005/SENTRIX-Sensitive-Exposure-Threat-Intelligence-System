from flask import Blueprint

tasks_bp = Blueprint("tasks", __name__)

# import to register routes
from . import js_discovery, leak_detection, validation, osint_correlation, risk_ml  # noqa: F401
