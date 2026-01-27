from datetime import datetime

def make_jsfile_doc(task_id, url, src, content, origin="external"):
    return {
        "task_id": task_id,
        "url": url,
        "src": src,
        "content": content,
        "origin": origin,
        "discovered_at": datetime.utcnow()
    }
