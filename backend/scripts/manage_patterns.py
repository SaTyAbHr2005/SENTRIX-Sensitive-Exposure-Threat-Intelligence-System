#!/usr/bin/env python3
"""
Pattern management script for sentrix leak detection
Allows disabling/enabling patterns and viewing pattern stats
"""
import os
import sys
from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")

def get_db():
    client = MongoClient(MONGO_URI)
    return client.get_default_database()

def list_patterns():
    """List all patterns with their details"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    patterns = list(coll.find({}))
    
    if not patterns:
        print("No patterns found in database.")
        return
    
    print(f"\n{'Rule ID':<30} {'Name':<30} {'Severity':<10} {'Category':<15} {'Enabled':<10} {'Source':<20}")
    print("=" * 125)
    
    for p in patterns:
        rule_id = p.get("rule_id", "N/A")[:29]
        name = p.get("name", "N/A")[:29]
        severity = p.get("severity", "N/A")[:9]
        category = p.get("category", "N/A")[:14]
        enabled = "✓" if p.get("enabled", True) else "✗"
        source = p.get("source", "N/A")[:19]
        
        print(f"{rule_id:<30} {name:<30} {severity:<10} {category:<15} {enabled:<10} {source:<20}")
    
    print(f"\nTotal patterns: {len(patterns)}")

def disable_pattern(rule_id):
    """Disable a specific pattern"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    result = coll.update_many(
        {"rule_id": rule_id},
        {"$set": {"enabled": False}}
    )
    print(f"Disabled {result.modified_count} pattern(s) with rule_id: {rule_id}")

def enable_pattern(rule_id):
    """Enable a specific pattern"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    result = coll.update_many(
        {"rule_id": rule_id},
        {"$set": {"enabled": True}}
    )
    print(f"Enabled {result.modified_count} pattern(s) with rule_id: {rule_id}")

def disable_category(category):
    """Disable all patterns in a category"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    result = coll.update_many(
        {"category": category},
        {"$set": {"enabled": False}}
    )
    print(f"Disabled {result.modified_count} pattern(s) in category: {category}")

def enable_category(category):
    """Enable all patterns in a category"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    result = coll.update_many(
        {"category": category},
        {"$set": {"enabled": True}}
    )
    print(f"Enabled {result.modified_count} pattern(s) in category: {category}")

def delete_pattern(rule_id):
    """Delete a specific pattern"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    result = coll.delete_many({"rule_id": rule_id})
    print(f"Deleted {result.deleted_count} pattern(s) with rule_id: {rule_id}")

def show_stats():
    """Show pattern statistics"""
    db = get_db()
    coll = db.get_collection("leak_patterns")
    
    total = coll.count_documents({})
    enabled = coll.count_documents({"enabled": True})
    disabled = coll.count_documents({"enabled": False})
    
    # Count by category
    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    by_category = list(coll.aggregate(pipeline))
    
    # Count by severity
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    by_severity = list(coll.aggregate(pipeline))
    
    print("\n=== Pattern Statistics ===")
    print(f"Total patterns: {total}")
    print(f"Enabled: {enabled}")
    print(f"Disabled: {disabled}")
    
    print("\n=== By Category ===")
    print(f"{'Category':<20} {'Count':<10}")
    print("-" * 30)
    for x in by_category:
        cat = x['_id'] if x['_id'] else "(none)"
        print(f"{cat:<20} {x['count']:<10}")
    
    print("\n=== By Severity ===")
    print(f"{'Severity':<20} {'Count':<10}")
    print("-" * 30)
    for x in by_severity:
        sev = x['_id'] if x['_id'] else "(none)"
        print(f"{sev:<20} {x['count']:<10}")

def main():
    if len(sys.argv) < 2:
        print("sentrix Pattern Management Tool")
        print("\nUsage:")
        print("  python manage_patterns.py list                        - List all patterns")
        print("  python manage_patterns.py stats                       - Show statistics")
        print("  python manage_patterns.py disable RULE_ID             - Disable a pattern")
        print("  python manage_patterns.py enable RULE_ID              - Enable a pattern")
        print("  python manage_patterns.py disable-category CATEGORY   - Disable all in category")
        print("  python manage_patterns.py enable-category CATEGORY    - Enable all in category")
        print("  python manage_patterns.py delete RULE_ID              - Delete a pattern")
        print("\nExamples:")
        print("  python manage_patterns.py disable FILE_PATH")
        print("  python manage_patterns.py disable-category info")
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_patterns()
    elif command == "stats":
        show_stats()
    elif command == "disable" and len(sys.argv) > 2:
        disable_pattern(sys.argv[2])
    elif command == "enable" and len(sys.argv) > 2:
        enable_pattern(sys.argv[2])
    elif command == "disable-category" and len(sys.argv) > 2:
        disable_category(sys.argv[2])
    elif command == "enable-category" and len(sys.argv) > 2:
        enable_category(sys.argv[2])
    elif command == "delete" and len(sys.argv) > 2:
        delete_pattern(sys.argv[2])
    else:
        print("Invalid command or missing arguments. Use 'python manage_patterns.py' for help.")

if __name__ == "__main__":
    main()
