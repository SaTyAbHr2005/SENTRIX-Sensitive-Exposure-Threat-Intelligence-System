# app/blueprints/tasks/leak_detection.py
from app.celery_app import celery
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import re
from typing import List, Dict
from app.models.leak import make_leak_doc
from app.utils.leak_detector import load_patterns_from_db, detect_leaks

try:
    import jsbeautifier
    _HAS_JSBEAUT = True
except Exception:
    _HAS_JSBEAUT = False

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo = MongoClient(MONGO_URI).get_default_database()


# ---------------------------------------------------------
# Regex (exact original LinkFinder regex)
# ---------------------------------------------------------
REGEX_JS_ENDPOINTS = re.compile(r"""

  (?:"|')                              

  (
    ((?:[a-zA-Z]{1,10}://|//)     
    [^"'/]{1,}\.                
    [a-zA-Z]{2,}[^"']{0,})     

    |

    ((?:/|\.\./|\./)            
    [^"'><,;| *()(%%$^/\\\[\]]  
    [^"'><,;|()]{1,})           

    |

    ([a-zA-Z0-9_\-/]{1,}/       
    [a-zA-Z0-9_\-/.]{1,}        
    \.(?:[a-zA-Z]{1,4}|action)  
    (?:[\?|#][^"|']{0,}|))      

    |

    ([a-zA-Z0-9_\-/]{1,}/        
    [a-zA-Z0-9_\-/]{3,}          
    (?:[\?|#][^"|']{0,}|))       

    |

    ([a-zA-Z0-9_\-]{1,}          
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml) 
    (?:[\?|#][^"|']{0,}|))       

  )

  (?:"|')                           

""", re.VERBOSE)


# ---------------------------------------------------------
# Beautifier (keeps original behavior; efficient fallback)
# ---------------------------------------------------------
def _beautify(js_text: str) -> str:
    if len(js_text) > 1_000_000:
        return js_text.replace(";", ";\n").replace(",", ",\n")

    if _HAS_JSBEAUT:
        try:
            return jsbeautifier.beautify(js_text)
        except Exception:
            pass

    return js_text


# ---------------------------------------------------------
# Context extraction (same logic as original, cleaned)
# ---------------------------------------------------------
def _extract_context(content: str, matches, delimiter="\n") -> List[Dict]:
    items = []
    max_i = len(content) - 1
    dlen = len(delimiter)

    for link, start, end in matches:
        cs = start
        ce = end

        # Move left
        while cs > 0 and content[cs - 1] != delimiter:
            cs -= 1

        # Move right
        while ce < max_i and content[ce] != delimiter:
            ce += 1

        # Cap context length to avoiding huge documents for minified lines
        raw_ctx = content[cs + dlen: ce]
        if len(raw_ctx) > 300:
             raw_ctx = raw_ctx[:300] + "..."

        items.append({
            "link": link,
            "context": raw_ctx
        })

    return items


# ---------------------------------------------------------
# MAIN FUNCTION — clean, reusable, no side effects
# ---------------------------------------------------------
def extract_endpoints(
    js_text: str,
    more_regex: str = None,
    include_context: bool = True
) -> List[Dict]:
    """
    Extract potential endpoints/paths/URLs from large JS content.

    Returns list of:
        { "link": str, "context": optional_str }

    Args:
        js_text:     Raw JavaScript text
        more_regex:  Optional filter (e.g., r"^/api/")
        include_context: whether to include extracted context

    Efficiency:
        - Beautification for readability (optional fallback)
        - Regex scanning on processed content
        - Deduplication by link
    """

    processed = _beautify(js_text) if include_context else js_text
    matches = [(m.group(1), m.start(0), m.end(0)) for m in REGEX_JS_ENDPOINTS.finditer(processed)]

    if include_context:
        items = _extract_context(processed, matches)
    else:
        items = [{"link": m.group(1)} for m in REGEX_JS_ENDPOINTS.finditer(processed)]

    # Dedup by link
    seen = set()
    deduped = []
    for item in items:
        link = item["link"]
        if link not in seen:
            seen.add(link)
            deduped.append(item)

    # Optional filtering
    if more_regex:
        regex = re.compile(more_regex)
        deduped = [i for i in deduped if regex.search(i["link"])]

    return deduped


@celery.task(bind=True, name="tasks.leak_detection")
def leak_detection(self, prev_res, task_id):
    js_coll = mongo.get_collection("js_files")
    leaks_coll = mongo.get_collection("leaks")
    tasks_coll = mongo.get_collection("tasks")
    logs_coll = mongo.get_collection("task_logs")

    # load patterns (cached)
    
    patterns = load_patterns_from_db()

    all_leaks = []
    all_endpoints = []

    # Mark task running
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": "Detecting leak"}}
    )

    # iterate js files belonging to this task
    for js in js_coll.find({"task_id": task_id}):
        js_id = str(js["_id"])
        content = js.get("content", "") or ""
        src = js.get("src") or "inline"
        page_url = js.get("url")

        # run detection
        detected = detect_leaks(content, src, patterns)

        for d in detected:
            # build leak doc with richer metadata
            leak_doc = make_leak_doc(
                task_id=task_id,
                jsfile_id=js_id,
                pattern=d.get("rule_name") or d.get("rule_id"),
                excerpt=d.get("snippet"),
                match=d.get("match"),
                severity=d.get("severity", "low"),
                category=d.get("category", "general"),
                rule_id=d.get("rule_id"),
                rule_source=d.get("rule_source"),
                url=page_url,
                source_file=src
            )
            ins = leaks_coll.insert_one(leak_doc)

            all_leaks.append({
                "leak_id": str(ins.inserted_id),
                "js_file_id": js_id,
                "pattern": d.get("rule_name"),
                "rule_id": d.get("rule_id"),
                "severity": d.get("severity"),
                "category": d.get("category"),
                "rule_source": d.get("rule_source"),
                "detector": d.get("detector"),
                "url": page_url,
                "source_file": src
            })

        # run endpoint discovery
        try:
            endpoints = extract_endpoints(content)
            for ep in endpoints:
                ep["js_file_id"] = js_id
                ep["source_file"] = src
                all_endpoints.append(ep)
        except Exception as e:
            print(f"[-] Endpoint extraction failed for {js_id}: {e}")

    # update the task with leak summary & status
    tasks_coll.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "results.leaks": all_leaks,
            "results.endpoints": all_endpoints[:1000],  # Cap to prevent DocumentTooLarge
            "status": "leak_detection_done"
        }}
    )

    # Calculate severity counts
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for l in all_leaks:
        s = (l.get("severity") or "low").lower()
        if s in sev_counts:
            sev_counts[s] += 1
        else:
            sev_counts["low"] += 1

    # append a task log
    try:
        logs_coll.insert_one({
            "task_id": task_id,
            "stage": "leak_detection",
            "message": f"Leak Detection Completed: Found {len(all_leaks)} leaks in total. Summary: High({sev_counts['high']}), Medium({sev_counts['medium']}), Low({sev_counts['low']}) | Endpoints found: {len(all_endpoints)}",
            "timestamp": __import__("datetime").datetime.utcnow(),
            "level": "info"
        })
    except Exception:
        pass

    return {"task_id": task_id, "leaks_found": len(all_leaks), "endpoints_found": len(all_endpoints)}
