from flask import Flask, jsonify, render_template
from .config import MONGO_URI
from .extensions import mongo
from app.utils.leak_detector import load_patterns_from_db

def create_app():
    app = Flask(__name__)

    # Flask only initializes Mongo (and routing)
    app.config["MONGO_URI"] = MONGO_URI

    # initialize extensions
    mongo.init_app(app)

    # register blueprints
    from .blueprints.scanner import scanner_bp
    from .blueprints.health import health_bp
    from .blueprints.tasks import tasks_bp

    load_patterns_from_db("/patterns")

    app.register_blueprint(scanner_bp, url_prefix="/api")
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(tasks_bp, url_prefix="/api")
    
    from .blueprints.chat import chat_bp
    app.register_blueprint(chat_bp, url_prefix="/api")

    # simple root
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    return app
