# app/blueprints/scanner/routes.py
from flask import request, jsonify, render_template
from . import scanner_bp
from ...extensions import mongo
from bson.objectid import ObjectId
from app.models.task import make_task_doc
from app.celery_app import celery
from celery import chain
import os


tasks_coll = mongo.cx.get_default_database().get_collection("tasks")
leaks_coll = mongo.cx.get_default_database().get_collection("leaks")



@scanner_bp.route("/start_scan", methods=["POST"])
def start_scan():
    payload = request.get_json(force=True)
    url = payload.get("url")
    if not url:
        targets = payload.get("targets")
        if isinstance(targets, list) and targets:
            url = targets[0]
    created_by = payload.get("created_by", "web")

    if not url:
        return jsonify({"error": "missing url"}), 400

    task_doc = make_task_doc(url=url, created_by=created_by)
    res = tasks_coll.insert_one(task_doc)
    task_id = str(res.inserted_id)

    # chain tasks
    workflow = chain(
        celery.signature("tasks.js_discovery", args=(task_id, url)),
        celery.signature("tasks.leak_detection", args=(task_id,)),
        celery.signature("tasks.validation", args=(task_id,)),
        celery.signature("tasks.osint_correlation", args=(task_id,)),
        celery.signature("tasks.risk_ml", args=(task_id,))
    )

    celery_result = workflow.apply_async()

    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"celery_task_id": celery_result.id, "status": "queued"}}
    )

    return jsonify({"task_id": task_id, "celery_task_id": celery_result.id}), 201


@scanner_bp.route("/task_status/<task_id>", methods=["GET"])
def task_status(task_id):
    try:
        doc = tasks_coll.find_one({"_id": ObjectId(task_id)})
        if not doc:
            return jsonify({"error": "not found"}), 404
        # convert ObjectId(s) to string where needed (top-level)
        doc["_id"] = str(doc["_id"])
        return jsonify(doc)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@scanner_bp.route("/stop_scan/<task_id>", methods=["POST"])
def stop_scan(task_id):
    try:
        doc = tasks_coll.find_one({"_id": ObjectId(task_id)})
        if not doc:
            return jsonify({"error": "not found"}), 404

        celery_id = doc.get("celery_task_id")
        if celery_id:
            celery.control.revoke(celery_id, terminate=True)
        tasks_coll.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": "stopped"}})
        return jsonify({"task_id": task_id, "revoked": celery_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@scanner_bp.route("/delete_task/<task_id>", methods=["POST"])
def delete_task(task_id):
    try:
        doc = tasks_coll.find_one({"_id": ObjectId(task_id)})
        if not doc:
            return jsonify({"error": "not found"}), 404

        # 1. Revoke Celery task if exists
        celery_id = doc.get("celery_task_id")
        if celery_id:
            celery.control.revoke(celery_id, terminate=True)

        # 2. Delete related data
        db = mongo.cx.get_default_database()
        db.get_collection("leaks").delete_many({"task_id": task_id})
        db.get_collection("js_files").delete_many({"task_id": task_id})
        db.get_collection("task_logs").delete_many({"task_id": task_id})

        # 3. Delete task doc
        tasks_coll.delete_one({"_id": ObjectId(task_id)})

        return jsonify({"success": True, "task_id": task_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400




@scanner_bp.route("/delete_all_tasks", methods=["POST"])
def delete_all_tasks():
    try:
        db = mongo.cx.get_default_database()
        
        # Get all celery task IDs
        all_tasks = list(tasks_coll.find({}, {"celery_task_id": 1}))
        
        # Revoke all running celery tasks
        for task in all_tasks:
            celery_id = task.get("celery_task_id")
            if celery_id:
                celery.control.revoke(celery_id, terminate=True)
        
        # Delete all related data
        db.get_collection("leaks").delete_many({})
        db.get_collection("js_files").delete_many({})
        db.get_collection("task_logs").delete_many({})
        tasks_coll.delete_many({})
        
        return jsonify({"success": True, "message": "All tasks deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@scanner_bp.route("/js_files/<task_id>", methods=["GET"])
def list_js_files(task_id):
    try:
        db = mongo.cx.get_default_database()
        js_coll = db.get_collection("js_files")

        files = list(js_coll.find({"task_id": task_id}, {
            "_id": 1,
            "src": 1,
            "origin": 1,
            "discovered_at": 1
        }))

        for f in files:
            f["_id"] = str(f["_id"])

        return jsonify({"task_id": task_id, "js_files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scanner_bp.route("/js_file/<js_id>", methods=["GET"])
def get_js_file(js_id):
    try:
        db = mongo.cx.get_default_database()
        js_coll = db.get_collection("js_files")

        doc = js_coll.find_one({"_id": ObjectId(js_id)})
        if not doc:
            return jsonify({"error": "JS file not found"}), 404

        doc["_id"] = str(doc["_id"])
        return jsonify(doc)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scanner_bp.route("/leaks/<task_id>", methods=["GET"])
def get_leaks(task_id):
    """
    Returns structured leaks for UI consumption.
    """
    try:
        db = mongo.cx.get_default_database()
        leaks_coll = db.get_collection("leaks")

        docs = list(leaks_coll.find({"task_id": task_id}))
        out = []
        for d in docs:
            doc = {
                "leak_id": str(d.get("_id")),
                "jsfile_id": d.get("jsfile_id"),
                "pattern": d.get("pattern"),
                "excerpt": d.get("excerpt"),
                "severity": d.get("severity"),
                "category": d.get("category"),
                "rule_id": d.get("rule_id"),
                "rule_source": d.get("rule_source"),
                "found_at": d.get("found_at"),
                "url": d.get("url"),
                "source_file": d.get("source_file"),
                "risk": d.get("risk", {}),
                "osint": d.get("osint", {})
            }
            out.append(doc)

        return jsonify({"task_id": task_id, "count": len(out), "leaks": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@scanner_bp.route("/task_logs/<task_id>", methods=["GET"])
def get_task_logs(task_id):
    try:
        db = mongo.cx.get_default_database()
        logs_coll = db.get_collection("task_logs")

        logs = list(logs_coll.find({"task_id": task_id}).sort([("timestamp", 1)]))

        out = []
        for l in logs:
            out.append({
                "log_id": str(l["_id"]),
                "stage": l.get("stage"),
                "message": l.get("message"),
                "level": l.get("level", "info"),
                "timestamp": l.get("timestamp")
            })

        return jsonify({"task_id": task_id, "logs": out})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scanner_bp.route("/tasks", methods=["GET"])
def list_tasks():
    try:
        limit = int(request.args.get("limit", 20))
        skip = int(request.args.get("skip", 0))
        
        cursor = tasks_coll.find({}).sort("created_at", -1).skip(skip).limit(limit)
        tasks = list(cursor)
        
        for t in tasks:
            t["_id"] = str(t["_id"])
            
        return jsonify({"tasks": tasks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scanner_bp.route("/stats", methods=["GET"])
def get_stats():
    try:
        # 1. Total Scans
        total_scans = tasks_coll.count_documents({})
        
        # 2. Status Distribution
        # Get all tasks and categorize their statuses
        all_tasks = list(tasks_coll.find({}, {"status": 1}))
        
        status_dist = {
            "finished": 0,
            "running": 0,
            "failed": 0,
            "queued": 0
        }
        
        # Categorize each task's status
        for task in all_tasks:
            status = task.get("status", "queued")
            
            # Map intermediate statuses to "running"
            if status in ["finished"]:
                status_dist["finished"] += 1
            elif status in ["failed", "stopped"]:
                status_dist["failed"] += 1
            elif status in ["queued"]:
                status_dist["queued"] += 1
            else:
                # All other statuses (running, Subdomain Enumeration, Scanning target, 
                # Detecting leak, js_discovery_done, leak_detection_done, validation_done, etc.)
                # are considered "running"
                status_dist["running"] += 1
        
        # 3. Risk Distribution (from tasks that have risk_ml results)
        # We'll categorize risk scores: High (>=70), Medium (40-69), Low (<40)
        risk_pipeline = [
            {"$match": {"results.risk_ml.score": {"$exists": True}}},
            {"$project": {
                "risk_level": {
                    "$switch": {
                        "branches": [
                            {"case": {"$gte": ["$results.risk_ml.score", 70]}, "then": "High"},
                            {"case": {"$gte": ["$results.risk_ml.score", 40]}, "then": "Medium"}
                        ],
                        "default": "Low"
                    }
                }
            }},
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
        ]
        
        risk_counts = list(tasks_coll.aggregate(risk_pipeline))
        risk_dist = {item["_id"]: item["count"] for item in risk_counts}
        
        # Ensure all keys exist
        for level in ["High", "Medium", "Low"]:
            if level not in risk_dist:
                risk_dist[level] = 0

        # 4. Leaks by Category (New Insight)
        leak_pipeline = [
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5} # Top 5 categories
        ]
        leak_counts = list(leaks_coll.aggregate(leak_pipeline))
        leaks_by_cat = {item["_id"] or "other": item["count"] for item in leak_counts}

        return jsonify({
            "total_scans": total_scans,
            "status_distribution": status_dist,
            "risk_distribution": risk_dist,
            "top_leak_categories": leaks_by_cat
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@scanner_bp.route("/stats/category_heatmap", methods=["GET"]) 
def category_heatmap():
    """
    Returns a heatmap matrix of leak counts per category (rows) and severity (columns).
    Expected output format:
    {
        "categories": ["API_KEY", "TOKEN", ...],
        "severities": ["High", "Medium", "Low"],
        "matrix": {
            "API_KEY": {"High": 5, "Medium": 2, "Low": 0},
            "TOKEN":   {"High": 1, "Medium": 3, "Low": 4},
            ...
        }
    }
    """
    try:
        # Ensure the leaks collection is available
        db = mongo.cx.get_default_database()
        leaks_coll = db.get_collection("leaks")
        # Normalise severity values to Title case for consistency
        pipeline = [
            {"$project": {"category": 1, "severity": {"$toUpper": "$severity"}}},
            {"$group": {"_id": {"category": "$category", "severity": "$severity"}, "count": {"$sum": 1}}},
            {"$sort": {"_id.category": 1, "_id.severity": 1}}
        ]
        rows = list(leaks_coll.aggregate(pipeline))
        # Build matrix dict
        matrix = {}
        categories_set = set()
        severities_set = set(["HIGH", "MEDIUM", "LOW"])  # expected levels
        for r in rows:
            cat = r["_id"]["category"] or "other"
            sev = r["_id"]["severity"]
            if sev not in severities_set:
                continue
            categories_set.add(cat)
            matrix.setdefault(cat, {"High": 0, "Medium": 0, "Low": 0})
            # Map to Title case keys
            matrix[cat][sev.title()] = r["count"]
        # Ensure every category has all three severity keys
        for cat in categories_set:
            matrix.setdefault(cat, {"High": 0, "Medium": 0, "Low": 0})
        # Build final result dict
        result = {
            "categories": sorted(list(categories_set)),
            "severities": ["High", "Medium", "Low"],
            "matrix": matrix
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


