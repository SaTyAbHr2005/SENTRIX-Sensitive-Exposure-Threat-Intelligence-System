import requests
import re
from urllib.parse import urlparse

def get_domain_from_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc

def discover_subdomains(domain):
    """
    Fetch subdomains using crt.sh (Certificate Transparency logs).
    Returns a list of unique subdomains (full URLs).
    """
    clean_domain = get_domain_from_url(domain)
    # Remove www. if present to get base domain
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]
        
    url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
    
    subdomains = set()
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    # crt.sh can return multi-line names
                    for sub in name_value.split("\n"):
                        sub = sub.strip()
                        if sub and not "*" in sub:
                            subdomains.add(sub)
    except Exception as e:
        print(f"Error fetching subdomains: {e}")
        
    # Convert to full URLs (assume https for now, or try both?)
    # For scanning purposes, we'll return the raw domains, caller can prepend protocol
    return list(subdomains)
