# app/models/leak.py
from datetime import datetime

def make_leak_doc(task_id, jsfile_id, pattern, excerpt, match=None, severity="low", category="general", rule_id=None, rule_source=None, url=None, source_file=None):
    return {
        "task_id": task_id,
        "jsfile_id": jsfile_id,
        "pattern": pattern,
        "excerpt": excerpt,
        "match": match,  # Stores the actual secret/string matched
        "severity": severity,
        "category": category,
        "rule_id": rule_id,
        "rule_source": rule_source,
        "url": url,
        "source_file": source_file,
        "found_at": datetime.utcnow()
    }
