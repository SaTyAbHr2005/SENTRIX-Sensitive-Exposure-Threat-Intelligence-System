import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Ensure backend matches python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.osint.correlator import correlate
from app.osint.rules import check_sensitive_file, check_admin_path, check_email_domain, detect_cloud_provider

# Mock Data
MOCK_OSINT_DATA = {
    "sensitive_files": {"config.xml", "id_rsa", ".env"},
    "disposable_domains": {"trashmail.com", "tempmail.org"},
    "free_domains": {"gmail.com", "yahoo.com"},
    "breached_org_domains": {"hacked-corp.com"},
    "admin_paths": {"admin", "wp-admin", "dashboard"},
    "cloud_fingerprints": {
        "aws": ["amazonaws", "cloudfront"],
        "azure": ["azure", "windows.net"],
        "cloudflare": ["cloudflare"]
    }
}

class TestOSINTModule(unittest.TestCase):
    
    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_sensitive_file_detection(self):
        self.assertTrue(check_sensitive_file("http://example.com/.env"))
        self.assertTrue(check_sensitive_file("/var/www/id_rsa"))
        self.assertFalse(check_sensitive_file("index.html"))

    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_admin_path_detection(self):
        self.assertTrue(check_admin_path("http://example.com/admin"))
        self.assertTrue(check_admin_path("/wp-admin"))
        self.assertTrue(check_admin_path("http://example.com/sub/dashboard"))
        # Strict segment matching check
        self.assertFalse(check_admin_path("/content/administration-guide")) 
        self.assertFalse(check_admin_path("/user/admin-fake"))
        self.assertFalse(check_admin_path("/user/login"))

    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_domain_classification(self):
        # Free
        res = check_email_domain("user@gmail.com")
        self.assertEqual(res["domain_type"], "free")
        
        # Disposable
        res = check_email_domain("fake@trashmail.com")
        self.assertEqual(res["domain_type"], "disposable")
        
        # Breached
        res = check_email_domain("ceo@hacked-corp.com")
        self.assertEqual(res["domain_type"], "breached_org")
        
        # None
        res = check_email_domain("admin@corp-secure.com")
        self.assertIsNone(res)

    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_cloud_fingerprint(self):
        # Headers check - use a string containing 'amazonaws'
        res = detect_cloud_provider({"Server": "my-server-amazonaws"}, [], [])
        self.assertIn("aws", res)
        
        # JS URL check - Must start with http
        res = detect_cloud_provider({}, [], ["https://d123.cloudfront.net/main.js"])
        self.assertIn("aws", res)
        
        # Ignore non-http JS (e.g. content)
        res = detect_cloud_provider({}, [], ["var x = 'amazonaws';"])
        self.assertNotIn("aws", res)
        
        # URL check
        res = detect_cloud_provider({}, ["http://test.azurewebsites.net"], [])
        self.assertIn("azure", res)
        
        # Determinism check (sorted)
        res = detect_cloud_provider({"Server": "cloudflare"}, ["http://test.azurewebsites.net"], [])
        self.assertEqual(res, ["azure", "cloudflare"])

    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_correlator_logic(self):
        findings = [
            {
                "_id": "1",
                "url": "http://target.com/.env",
                "source_file": "http://target.com/.env",
                "excerpt": "DB_PASSWORD=123",
                "category": "GENERIC"
            },
            {
                "_id": "2",
                "url": "http://target.com/contact",
                "source_file": "main.js", # Should trigger public artifact
                "excerpt": "bob@trashmail.com", # Should trigger disposable domain
                "category": "EMAIL"
            },
            {
                "_id": "3",
                "url": "http://target.com/safe",
                "source_file": "index.html",
                "excerpt": "Nothing here",
                "category": "INFO"
            }
        ]
        
        crawl_context = {
            "headers": {"Server": "cloudflare"},
            "urls": [],
            "js_files": []
        }
        
        results = correlate(findings, crawl_context)
        
        # Finding 1: Sensitive File + Global Cloud
        f1 = next(f for f in findings if f["_id"] == "1")
        labels1 = f1["osint"]["labels"]
        self.assertIn("KNOWN_SENSITIVE_FILE", labels1)
        self.assertIn("INFRASTRUCTURE_FINGERPRINT_EXPOSED", labels1)
        self.assertEqual(f1["osint"]["metadata"]["cloud_provider"], "cloudflare")
        
        # Finding 2: Email + JS + Global Cloud
        f2 = next(f for f in findings if f["_id"] == "2")
        labels2 = f2["osint"]["labels"]
        self.assertIn("HIGH_RISK_DOMAIN_CONTEXT", labels2) 
        self.assertIn("PUBLICLY_EXPOSED_ARTIFACT", labels2)
        self.assertIn("INFRASTRUCTURE_FINGERPRINT_EXPOSED", labels2)
        
        # Finding 3: Global Cloud but NO public exposure -> Should NOT have cloud label -> NO_OSINT_SIGNAL
        f3 = next(f for f in findings if f["_id"] == "3")
        labels3 = f3["osint"]["labels"]
        self.assertIn("NO_OSINT_SIGNAL", labels3)
        self.assertNotIn("INFRASTRUCTURE_FINGERPRINT_EXPOSED", labels3)

    @patch("app.osint.rules.OSINT_DATA", MOCK_OSINT_DATA)
    def test_no_signal(self):
        findings = [{"_id": "4", "url": "foo", "source_file": "bar", "excerpt": "baz"}]
        # No cloud context
        crawl_context = {"headers": {}, "urls": [], "js_files": []}
        
        results = correlate(findings, crawl_context)
        f4 = results[0]
        self.assertIn("NO_OSINT_SIGNAL", f4["osint"]["labels"])

if __name__ == "__main__":
    unittest.main()
