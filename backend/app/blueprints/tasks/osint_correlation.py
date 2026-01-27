# app/blueprints/tasks/osint_correlation.py
from app.celery_app import celery
from pymongo import MongoClient
import os
from bson.objectid import ObjectId
from app.osint.correlator import correlate
import logging

logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database()

@celery.task(bind=True, name="tasks.osint_correlation")
def osint_correlation(self, prev_res, task_id):
    """
    Module 4: OSINT Exposure Correlation
    """
    leaks_coll = db.get_collection("leaks")
    tasks_coll = db.get_collection("tasks")
    js_coll = db.get_collection("js_files")
    
    # Get scan target details for context
    task_doc = tasks_coll.find_one({"_id": ObjectId(task_id)})
    if not task_doc:
        logger.error(f"Task {task_id} not found during OSINT correlation")
        return {}
        
    target_url = task_doc.get("url", "")
    
    # Gather JS file URLs for fingerprinting
    # We use 'src' or 'origin' if available. 
    js_cursor = js_coll.find({"task_id": task_id}, {"src": 1, "origin": 1})
    js_urls = []
    for doc in js_cursor:
        if doc.get("src"):
            js_urls.append(doc["src"])
        elif doc.get("origin"):
             js_urls.append(doc["origin"])
             
    # Construct Crawl Context
    # Note: Headers might not be captured in current pipeline DB schema, so we default to empty.
    crawl_context = {
        "headers": {}, 
        "urls": [target_url] + js_urls,
        "js_files": js_urls # Passing URLs for fast fingerprinting
    }
    
    # Fetch all findings (leaks)
    findings = list(leaks_coll.find({"task_id": task_id}))
    
    # Run Correlation
    # correlate modifies the list of dicts in-place or returns them
    enriched_findings = correlate(findings, crawl_context)
    
    # Save back to DB
    osint_summary = {
        "KNOWN_SENSITIVE_FILE": 0,
        "EXPOSED_ADMIN_PATH": 0,
        "PUBLICLY_EXPOSED_ARTIFACT": 0,
        "HIGH_RISK_DOMAIN_CONTEXT": 0,
        "INFRASTRUCTURE_FINGERPRINT_EXPOSED": 0,
        "SECRET_REUSE_DETECTED": 0,
        "NO_OSINT_SIGNAL": 0
    }
    
    for f in enriched_findings:
        osint_data = f.get("osint", {})
        
        # Update leak
        leaks_coll.update_one(
            {"_id": f["_id"]},
            {"$set": {"osint": osint_data}}
        )
        
        # Update summary
        for label in osint_data.get("labels", []):
            if label in osint_summary:
                osint_summary[label] += 1
                
    # Update Task Status
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "results.osint_correlation": osint_summary,
            "status": "osint_correlation_done"
        }}
    )
    
    return osint_summary
