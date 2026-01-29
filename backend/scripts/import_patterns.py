# backend/scripts/import_patterns.py
import os
import yaml
import glob
from pymongo import MongoClient
from datetime import datetime

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
PATTERN_DIR = os.getenv("PATTERN_DIR", "./patterns")

client = MongoClient(MONGO_URI)
db = client.get_default_database()
coll = db.get_collection("leak_patterns")

def normalize_rule(name, cfg, source_file):
    return {
        "rule_id": cfg.get("id") or name,
        "name": cfg.get("name") or name,
        "regex": cfg.get("regex"),
        "severity": cfg.get("severity", "low"),
        "category": cfg.get("category", "info"),
        "source": source_file,
        "enabled": cfg.get("enabled", True),
        "meta": cfg.get("meta", {}),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }

def import_file(path):
    src = os.path.basename(path)
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
        for name, cfg in data.items():
            if "regex" not in cfg:
                continue
            rule = normalize_rule(name, cfg, src)
            # upsert by rule_id + source
            coll.update_one(
                {"rule_id": rule["rule_id"], "source": rule["source"]},
                {"$set": rule},
                upsert=True
            )

def main():
    files = glob.glob(os.path.join(PATTERN_DIR, "*.*"))
    if not files:
        print("No pattern files found in", PATTERN_DIR)
        return
    for f in files:
        print("Importing", f)
        import_file(f)
    print("Done.")

if __name__ == "__main__":
    main()
