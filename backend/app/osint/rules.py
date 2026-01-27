from .loader import OSINT_DATA
import re

def check_sensitive_file(path):
    """
    Checks if the file path matches known sensitive files.
    """
    if not path:
        return False
        
    filename = path.split('/')[-1].lower()
    return filename in OSINT_DATA["sensitive_files"]

def check_admin_path(path):
    """
    Checks if the path matches known admin panels.
    """
    if not path:
        return False
        
    cleaned_path = path.strip('/')
    
    # Only match full path segments, not substrings
    parts = [p.lower() for p in cleaned_path.split('/') if p]
    return any(p in OSINT_DATA["admin_paths"] for p in parts)

def check_email_domain(email):
    """
    Checks email domain against disposable, free, or breached lists.
    Returns domain context dict or None.
    """
    if not email or "@" not in email:
        return None
        
    try:
        domain = email.split('@')[1].lower().strip()
    except IndexError:
        return None
        
    domain_type = None
    
    if domain in OSINT_DATA["disposable_domains"]:
        domain_type = "disposable"
    elif domain in OSINT_DATA["breached_org_domains"]:
        domain_type = "breached_org"
    elif domain in OSINT_DATA["free_domains"]:
        domain_type = "free"
    
    if domain_type:
        return {
            "domain_type": domain_type,
            "domain": domain
        }
    
    return None

def detect_cloud_provider(headers, urls, js_files):
    """
    Fingerprints cloud providers based on headers, URLs, and JS content.
    Returns sorted list of provider names.
    """
    providers = set()
    search_space = []
    
    # Headers check
    if isinstance(headers, dict):
        for k, v in headers.items():
            search_space.append(str(k).lower())
            search_space.append(str(v).lower())
            
    # URLs check
    if urls:
        search_space.extend([u.lower() for u in urls])
        
    # JS Files check - Only scan JS URLs, not content
    if js_files:
        for j in js_files:
            if isinstance(j, str) and j.startswith("http"):
                search_space.append(j.lower())
                
    # Check indicators against search space
    for provider, indicators in OSINT_DATA["cloud_fingerprints"].items():
        for indicator in indicators:
            for entry in search_space:
                if indicator in entry:
                    providers.add(provider)
                    break
                    
    return sorted(list(providers))
