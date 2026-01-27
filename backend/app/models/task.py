from datetime import datetime
from bson.objectid import ObjectId

def make_task_doc(url, created_by="system"):
    return {
        "url": url,
        "status": "pending",   # pending, running, stopped, finished, failed
        "created_by": created_by,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),    
        "celery_task_id": None,
        "results": {},
    }

def update_timestamp(doc):
    doc["updated_at"] = datetime.utcnow()
    return doc
