import os
import hashlib
from collections import deque
from bson.objectid import ObjectId
from pymongo import MongoClient
from bs4 import BeautifulSoup

from app.celery_app import celery
from app.models.js_file import make_jsfile_doc
from app.models.task import update_timestamp

# Crawler logic
from app.utils.crawler.safe_get import safe_get
from app.utils.crawler.extractors import (
    extract_js_urls_from_html,
    extract_nested_js,
    normalize_url
)
from app.utils.subdomain_enum import discover_subdomains

# Mongo for worker process
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client.get_default_database()


@celery.task(bind=True, name="tasks.js_discovery", soft_time_limit=120, time_limit=150)
def js_discovery(self, task_id, start_url, max_js=200, crawl_subdomains=True):
    tasks_coll = db.get_collection("tasks")
    js_coll = db.get_collection("js_files")
    
    print(f"[DEBUG] js_discovery started for task_id={task_id}, url={start_url}")

    # Mark task running
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": "running"}}
    )

    visited = set()
    queue = deque()
    discovered = []
    inline_seen = set()

    # Determine URLs to scan (start_url + subdomains)
    urls_to_scan = [start_url]
    if crawl_subdomains:
        tasks_coll.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {"status": "Subdomain Enumeration"}}
        )
        try:
            subs = discover_subdomains(start_url)
            # Limit to top 10 subdomains to avoid timeout for now
            for s in subs[:10]:
                if not s.startswith("http"):
                    urls_to_scan.append(f"https://{s}")
                else:
                    urls_to_scan.append(s)
        except Exception as e:
            print(f"Subdomain discovery failed: {e}")

    # Deduplicate
    urls_to_scan = list(set(urls_to_scan))

    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": "Scanning target"}}
    )

    # Phase 1: Scan all HTML pages (main + subdomains) for JS
    for page_url in urls_to_scan:
        res = safe_get(page_url)
        if not res["ok"]:
            continue
        html = res["response"].text

        # Extract external JS URLs
        external_js_urls = extract_js_urls_from_html(html, page_url)
        for js_url in external_js_urls:
            if js_url and js_url not in visited:
                queue.append(js_url)
        
        # Extract inline scripts using BeautifulSoup
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script_tag in soup.find_all('script'):
                # Skip external scripts (already handled above)
                if script_tag.get('src'):
                    continue
                
                content = script_tag.string or script_tag.get_text()
                if not content:
                    continue
                
                content = content.strip()
                if not content or len(content) > 500_000:
                    continue
                
                # Deduplicate inline scripts by hash
                h = hashlib.sha256(content.encode()).hexdigest()
                if h in inline_seen:
                    continue
                inline_seen.add(h)

                doc = make_jsfile_doc(
                    task_id=task_id,
                    url=page_url,
                    src=None,
                    content=content,
                    origin="inline"
                )
                inserted = js_coll.insert_one(doc)
                discovered.append({
                    "type": "inline",
                    "id": str(inserted.inserted_id),
                    "snippet": content[:200]
                })
        except Exception as e:
            print(f"Error parsing HTML for inline scripts: {e}")


    # BFS crawl nested JS
    while queue and len(visited) < max_js:
        js_url = queue.popleft()
        js_url = normalize_url(start_url, js_url)

        if not js_url or js_url in visited:
            continue
        visited.add(js_url)

        res = safe_get(js_url)
        if not res["ok"]:
            continue
        content = res["response"].text or ""
        if not content or len(content) > 2_000_000:
            continue

        doc = make_jsfile_doc(
            task_id=task_id,
            url=js_url,
            src=js_url,
            content=content,
            origin="external"
        )
        inserted = js_coll.insert_one(doc)
        discovered.append({
            "type": "external",
            "src": js_url,
            "id": str(inserted.inserted_id)
        })

        nested = extract_nested_js(content, js_url)
        for n in nested:
            n = normalize_url(js_url, n)
            if n and n not in visited and n not in queue:
                queue.append(n)

        # Update progress without list membership lookup cost
        if len(visited) % 5 == 0:
            tasks_coll.update_one(
                {"_id": ObjectId(task_id)},
                {"$set": {"progress": f"{len(visited)} files"}}
            )

    # Mark finished safely, preserve created_at using setOnInsert
    ts = update_timestamp({})["updated_at"]
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {
            "$set": {
                "status": "js_discovery_done",
                "results.js_discovery": discovered,
                "updated_at": ts
            }
        }
    )

    return {"success": True, "discovered": discovered}
