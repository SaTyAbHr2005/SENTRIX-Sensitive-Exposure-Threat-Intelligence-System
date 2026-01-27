import re
from urllib.parse import urljoin

JS_EXTRACT_REGEX = re.compile(
    r'''(?i)
    (?:src|href|data-main|ng-include|ng-src|fetch|import|require|
       createElement|appendChild|innerHTML|getScript)
       \s*=\s*["']([^"']+\.js[^"']*)["']
    ''',
    re.VERBOSE
)

DEEP_JS_PATTERNS = [
    re.compile(r'import\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]\s*\)'),
    re.compile(r'import\s+.*?\s+from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]'),
    re.compile(r'require\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]\s*\)'),
    re.compile(r'//#\s*sourceMappingURL=([^\s]+)')
]


def normalize_url(base_url, js_url):
    if not js_url or len(js_url) > 500:
        return None

    js_url = js_url.strip()

    if js_url.startswith(("http://", "https://")):
        return js_url
    if js_url.startswith("//"):
        return "https:" + js_url
    if js_url.startswith("/"):
        return urljoin(base_url, js_url)

    return urljoin(base_url, js_url)


def extract_js_urls_from_html(html, base_url):
    found = set()
    for m in JS_EXTRACT_REGEX.findall(html):
        norm = normalize_url(base_url, m)
        if norm and norm.startswith(("http://", "https://")) and ".js" in norm:
            found.add(norm)
    return list(found)


def extract_nested_js(content, base_url):
    found = set()
    for regex in DEEP_JS_PATTERNS:
        for m in regex.findall(content):
            if not m or m.startswith("data:"):
                continue
            norm = normalize_url(base_url, m)
            if norm and norm.startswith(("http://", "https://")) and ".js" in norm:
                found.add(norm)
    return list(found)
