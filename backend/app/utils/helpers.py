import re
from bs4 import BeautifulSoup

def extract_scripts_from_html(html):
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    results = []
    seen = set()

    for tag in soup.find_all("script"):
        src = tag.get("src")
        script_type = "external" if src else "inline"
        content = "" if src else tag.get_text(strip=True)

        key = (script_type, src, content)
        if key in seen:
            continue  # removing dedupe with the help of seen
        seen.add(key)

        results.append({
            "type": script_type,
            "src": src,
            "content": content
        })

    return results

def normalize_url(base, url):
    from urllib.parse import urljoin
    return urljoin(base, url)
