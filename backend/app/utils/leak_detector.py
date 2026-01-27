# app/utils/leak_detector.py
import os
import re
import time
import hashlib
import yaml
from functools import lru_cache
from pymongo import MongoClient
import esprima

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
mongo = MongoClient(MONGO_URI).get_default_database()

# Small fallback patterns (kept intentionally minimal)  
FALLBACK_PATTERNS = [
    {
        "rule_id": "fallback_bearer",
        "label": "Authorization: Bearer token",
        "regex": r"[Bb]earer\s+[A-Za-z0-9\-\._+/=]{10,}",
        "severity": "high",
        "category": "auth",
        "source": "fallback",
        "enabled": True
    },
    {
        "rule_id": "fallback_basic",
        "label": "Authorization: Basic",
        "regex": r"[Bb]asic\s+[A-Za-z0-9+/=]{10,}",
        "severity": "high",
        "category": "auth",
        "source": "fallback",
        "enabled": True
    },
    {
        "rule_id": "fallback_private_key",
        "label": "Private Key PEM",
        "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "severity": "critical",
        "category": "credentials",
        "source": "fallback",
        "enabled": True
    },
]

_CACHE_TTL = int(os.getenv("LEAK_PATTERN_CACHE_TTL", "300"))  # seconds
_cache_loaded_at = 0
_cached_compiled = None

def _compile_rule(doc):
    """
    Normalize and compile a rule dict (from DB or fallback).
    """
    raw = doc.get("regex") or doc.get("pattern") or doc.get("raw_regex")
    if not raw:
        return None
    try:
        compiled = re.compile(raw, re.I | re.M | re.S)
    except Exception:
        return None

    return {
        "rule_id": doc.get("rule_id") or doc.get("id") or doc.get("name"),
        "label": doc.get("name") or doc.get("label") or doc.get("rule_id") or "unnamed",
        "regex": compiled,
        "raw_regex": raw,
        "severity": doc.get("severity", "low"),
        "category": doc.get("category", "general"),
        "source": doc.get("source", "db"),
        "enabled": bool(doc.get("enabled", True))
    }


def load_patterns_from_db(force_reload=False):
    """
    Load (and cache) patterns from Mongo + fallback.
    Returns list of compiled rule dicts.
    """
    global _cache_loaded_at, _cached_compiled
    now = time.time()
    if _cached_compiled and not force_reload and (now - _cache_loaded_at) < _CACHE_TTL:
        return _cached_compiled

    coll = mongo.get_collection("leak_patterns")
    docs = list(coll.find({}))

    compiled = []
    # DB rules: doc structure expected to have "rules" map if uploaded via importer,
    # or be flat rule documents.
    for doc in docs:
        # if file-import style (doc has "rules" mapping)
        if isinstance(doc.get("rules"), dict):
            for name, rdoc in doc["rules"].items():
                r = {
                    "rule_id": rdoc.get("id") or name,
                    "name": rdoc.get("name") or name,
                    "regex": rdoc.get("regex") or rdoc.get("pattern"),
                    "severity": rdoc.get("severity", "medium"),
                    "category": rdoc.get("category", "general"),
                    "source": doc.get("file_name") or doc.get("source", "db"),
                    "enabled": rdoc.get("enabled", True)
                }
                c = _compile_rule(r)
                if c:
                    compiled.append(c)
        else:
            # flat rule doc
            c = _compile_rule(doc)
            if c:
                compiled.append(c)

    # add fallback rules (ensure no duplication by rule_id)
    existing_ids = {r["rule_id"] for r in compiled if r.get("rule_id")}
    for f in FALLBACK_PATTERNS:
        if f["rule_id"] not in existing_ids:
            c = _compile_rule(f)
            if c:
                compiled.append(c)

    _cached_compiled = compiled
    _cache_loaded_at = now
    return compiled


def force_reload_patterns():
    return load_patterns_from_db(force_reload=True)


def _snippet_from_pos(text, start, end, ctx=80):
    s = max(0, start - ctx)
    e = min(len(text), end + ctx)
    return text[s:e]


def _detect_literals_ast(content):
    """
    Simple AST literal extractor using esprima. Returns a set of string literals.
    """
    literals = []
    try:
        tree = esprima.parseScript(content, tolerant=True)
    except Exception:
        return literals

    def walk(node):
        if isinstance(node, dict):
            t = node.get("type")
            if t == "Literal" and isinstance(node.get("value"), str):
                v = node.get("value")
                literals.append(v)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for it in node:
                walk(it)
    walk(tree)
    return literals


def _is_false_positive(match, snippet, rule_id, category):
    """
    Filter out common false positives that aren't actually security leaks.
    Returns True if this match should be filtered out.
    """
    if not match:
        return True
    
    # Normalize for checking
    match_lower = match.lower()
    snippet_lower = snippet.lower()
    
    # Filter URL patterns (HTTPS_URL, HTTP_URL, etc.)
    if rule_id and any(x in rule_id.lower() for x in ['url', 'http', 'https']):
        # Check if it's a URL assignment in JavaScript
        if any(pattern in snippet_lower for pattern in [
            '.src=',
            'src="',
            "src='",
            '.href=',
            'href="',
            "href='",
            'iframe.src',
            'window.location',
            'location.href',
            'ajax(',
            'axios(',
            'fetch(',
        ]):
            return True
        
    if rule_id and "file" in rule_id.lower() or category == "info":
        if match.startswith(('/node_modules',)):
            return True

    if any(indicator in snippet_lower for indicator in [
        'new_script.src', 
        'script.src',
        'link.href',
        'img.src',
        'iframe.src',
        'window.location',
        'document.getelementsby',
        '.appendchild',
        'addeventlistener',
    ]):
        return True
    
    # Very short matches are usually noise
    if len(match.strip()) < 8:
        return True
    
    # Common example/placeholder values
    placeholder_patterns = [
        r'example\.com',
        r'test\.com',
        r'localhost',
        r'127\.0\.0\.1',
        r'YOUR_API_KEY',
        r'INSERT_.*_HERE',
        r'REPLACE_ME',
        r'TODO',
        r'xxx+',
    ]
    for pattern in placeholder_patterns:
        if re.search(pattern, match, re.I):
            return True
    
    return False


def detect_leaks(content, source_url_or_label, patterns=None):
    """
    Run detection on JS content and return structured list.
    Each entry:
      {
        rule_id, rule_name, severity, category, rule_source,
        snippet, match, reason: "regex"|"ast"
      }
    """
    if patterns is None:
        patterns = load_patterns_from_db()

    leaks = []
    content = content or ""

    # Regex-based detection (use finditer to extract positions)
    for rule in patterns:
        if not rule.get("enabled"):
            continue
        regex = rule.get("regex")
        if not regex:
            continue
        for m in regex.finditer(content):
            matched = None
            try:
                groups = m.groups()
                if groups:
                    for g in groups:
                        if g:
                            matched = g
                            break
                if not matched:
                    matched = m.group(0)
            except Exception:
                matched = m.group(0) if m else ""

            snippet = _snippet_from_pos(content, m.start(), m.end(), ctx=80)
            
            # Apply false positive filtering
            if _is_false_positive(matched, snippet, rule.get("rule_id"), rule.get("category")):
                continue
            
            leaks.append({
                "rule_id": rule.get("rule_id"),
                "rule_name": rule.get("label"),
                "severity": rule.get("severity", "low"),
                "category": rule.get("category", "general"),
                "rule_source": rule.get("source"),
                "snippet": snippet,
                "match": matched,
                "source": source_url_or_label,
                "detector": "regex"
            })

    # AST-based search (string literals) - low-noise: check likely candidates
    literals = _detect_literals_ast(content)
    for lit in literals:
        if not isinstance(lit, str):
            continue
        if len(lit) < 12:
            continue
        # heuristic: contains secret-like keywords
        if re.search(r"(secret|token|api[_-]?key|access|passwd|password|private_key|client_secret)", lit, re.I):
            # Also filter AST findings
            if _is_false_positive(lit, lit, "ast_literal", "ast"):
                continue
                
            leaks.append({
                "rule_id": "ast_literal",
                "rule_name": "AST Suspicious Literal",
                "severity": "low",
                "category": "ast",
                "rule_source": "ast",
                "snippet": lit[:400],
                "match": lit,
                "source": source_url_or_label,
                "detector": "ast"
            })

    # dedupe by (rule_id, match, source)
    out = []
    seen = set()
    for l in leaks:
        key = (l.get("rule_id"), l.get("match"), l.get("source"))
        if key in seen:
            continue
        seen.add(key)
        out.append(l)

    return out
