# app/blueprints/tasks/validation.py
from app.celery_app import celery
from pymongo import MongoClient
import os
from bson.objectid import ObjectId
from app.utils.validation_analyzer import ValidationAnalyzer

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database()

@celery.task(bind=True, name="tasks.validation")
def validation(self, prev_res, task_id):
    """
    Module 3: Offline Validation of Detected Secrets.
    """
    leaks_coll = db.get_collection("leaks")
    tasks_coll = db.get_collection("tasks")
    js_coll = db.get_collection("js_files")
    
    analyzer = ValidationAnalyzer()
    
    # 1. Validate Leak Candidates
    leaks = list(leaks_coll.find({"task_id": task_id}))
    validation_summary = {
        "valid": 0,
        "likely": 0,
        "invalid": 0,
        "total": len(leaks)
    }
    
    for leak in leaks:
        secret = leak.get("match") or ""
        rule_id = leak.get("rule_id", "").lower()
        category = leak.get("category", "").lower()
        
        # Infer type
        s_type = "generic"
        if "jwt" in rule_id:
            s_type = "jwt"
        elif "email" in rule_id or "mail" in rule_id:
            s_type = "email"
        elif "key" in rule_id or "secret" in rule_id:
            s_type = "api_key"
            
        # Analyze
        res = analyzer.analyze(secret, s_type)
        
        # Update leak with validation results
        leaks_coll.update_one(
            {"_id": leak["_id"]},
            {"$set": {"validation": res}}
        )
        
        if res["label"] in validation_summary:
            validation_summary[res["label"]] += 1

    # 2. Basic JS Validation (Legacy check preserved)
    js_issues = []
    try:
        for j in js_coll.find({"task_id": task_id}):
            content = j.get("content") or ""
            if len(content) == 0:
                 js_issues.append({"jsfile": str(j["_id"]), "issue": "empty"})
            elif len(content) > 1_000_000: # 1MB limit for warning
                 js_issues.append({"jsfile": str(j["_id"]), "issue": "oversized"})
    except Exception:
        pass

    # Store results in Task
    results = {
        "leak_validation_summary": validation_summary,
        "js_issues": js_issues
    }
    
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)}, 
        {"$set": {
            "results.validation": results,
            "status": "validation_done"
        }}
    )
    
    return results
