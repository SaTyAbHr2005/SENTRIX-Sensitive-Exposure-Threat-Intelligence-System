# app/blueprints/tasks/risk_ml.py
from app.celery_app import celery
from pymongo import MongoClient
import os
from bson.objectid import ObjectId
from app.risk.engine import risk_engine
import logging

logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database()

@celery.task(bind=True, name="tasks.risk_ml")
def risk_ml(self, prev_res, task_id):
    """
    Module 5: AI Risk Classifier
    Applies hybrid rule-based + ML risk scoring to all detected leaks.
    """
    leaks_coll = db.get_collection("leaks")
    tasks_coll = db.get_collection("tasks")
    
    logger.info(f"[RISK_ML] Starting risk assessment for task_id={task_id}")
    
    # Fetch all findings (leaks) for this task
    findings = list(leaks_coll.find({"task_id": task_id}))
    
    if not findings:
        logger.warning(f"[RISK_ML] No leaks found for task_id={task_id}")
        tasks_coll.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {
                "results.risk_ml": {"score": 0, "severity": "Low", "total_leaks": 0},
                "status": "finished"
            }}
        )
        return {"score": 0, "total_leaks": 0}
    
    # Apply Risk Engine to all findings
    try:
        enriched_findings = risk_engine.assess_risk(findings)
    except Exception as e:
        logger.error(f"[RISK_ML] Risk engine failed: {e}")
        # Fallback to basic scoring if ML fails
        enriched_findings = findings
        for f in enriched_findings:
            f["risk"] = {
                "score": 50,
                "severity": "Medium",
                "factors": ["ML engine unavailable - default score applied"]
            }
    
    # Save risk assessments back to leaks collection
    for finding in enriched_findings:
        risk_data = finding.get("risk", {})
        score = risk_data.get("score")
        logger.info(f"[RISK_ML] Leak {finding.get('_id')} -> Score: {score}, Severity: {risk_data.get('severity')}, Factors: {risk_data.get('factors')}")
        
        leaks_coll.update_one(
            {"_id": finding["_id"]},
            {"$set": {"risk": risk_data}}
        )
    
    # Calculate aggregate risk score for the task
    scores = [f.get("risk", {}).get("score", 0) for f in enriched_findings]
    avg_score = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    
    # Determine overall severity
    if max_score >= 80:
        overall_severity = "High"
    elif max_score >= 40:
        overall_severity = "Medium"
    else:
        overall_severity = "Low"
    
    # Summary for task
    risk_summary = {
        "score": int(max_score),  # Use max score for task-level assessment
        "avg_score": int(avg_score),
        "severity": overall_severity,
        "total_leaks": len(enriched_findings),
        "high_risk_count": sum(1 for s in scores if s >= 80),
        "medium_risk_count": sum(1 for s in scores if 40 <= s < 80),
        "low_risk_count": sum(1 for s in scores if s < 40)
    }
    
    # Update task status
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "results.risk_ml": risk_summary,
            "status": "finished"
        }}
    )
    
    logger.info(f"[RISK_ML] Completed risk assessment: {risk_summary}")
    
    return risk_summary
