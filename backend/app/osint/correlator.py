from .rules import (
    check_sensitive_file,
    check_admin_path,
    check_email_domain,
    detect_cloud_provider
)

OSINT_LABELS = {
    "KNOWN_SENSITIVE_FILE": "KNOWN_SENSITIVE_FILE",
    "EXPOSED_ADMIN_PATH": "EXPOSED_ADMIN_PATH",
    "PUBLICLY_EXPOSED_ARTIFACT": "PUBLICLY_EXPOSED_ARTIFACT",
    "HIGH_RISK_DOMAIN_CONTEXT": "HIGH_RISK_DOMAIN_CONTEXT",
    "INFRASTRUCTURE_FINGERPRINT_EXPOSED": "INFRASTRUCTURE_FINGERPRINT_EXPOSED",
    "SECRET_REUSE_DETECTED": "SECRET_REUSE_DETECTED",
    "NO_OSINT_SIGNAL": "NO_OSINT_SIGNAL"
}

def correlate(findings, crawl_context):
    """
    Main OSINT engine.
    Enriches findings with public exposure context.
    
    :param findings: List of finding dicts (from validation stage).
    :param crawl_context: Dict containing 'headers', 'urls', 'js_files' of the scan target.
    :return: List of enriched findings.
    """
    if not findings:
        return []

    # Extract global context once
    target_headers = crawl_context.get("headers", {})
    target_urls = crawl_context.get("urls", [])
    target_js_files = crawl_context.get("js_files", [])
    
    # Cloud providers are usually target-wide, not just per finding, 
    # but we can check if a finding reveals a specific provider too.
    # For now, we detect global cloud context.
    global_providers = detect_cloud_provider(target_headers, target_urls, target_js_files)
    
    for finding in findings:
        labels = []
        metadata = {
            "domain": None,
            "domain_type": None,
            "cloud_provider": None,
            "exposure_surface": None
        }

        # extracting relevant fields from finding
        # Assuming finding structure has 'source_file', 'url', 'excerpt', 'decoded_content' etc.
        # Modifying based on typical structure seen in ValidationAnalyzer
        
        f_url = finding.get("url", "")
        f_source = finding.get("source_file", "")
        f_excerpt = finding.get("excerpt", "")
        
        # 1. Sensitive file exposure
        if check_sensitive_file(f_url) or check_sensitive_file(f_source):
            labels.append(OSINT_LABELS["KNOWN_SENSITIVE_FILE"])
            metadata["exposure_surface"] = "sensitive_file"

        # 2. Admin path exposure
        if check_admin_path(f_url) or check_admin_path(f_source):
            labels.append(OSINT_LABELS["EXPOSED_ADMIN_PATH"])
             # If not already set
            if not metadata.get("exposure_surface"):
                metadata["exposure_surface"] = "admin_path"

        # 3. Email domain context
        # Check if finding is an email or contains an email
        # The 'finding' might have a 'type' field being 'email'
        email_candidate = None
        if finding.get("category") == "EMAIL": # Assuming category name
             email_candidate = finding.get("secret") or finding.get("excerpt") # 'secret' holds the actual value
        elif "@" in f_excerpt and "." in f_excerpt.split("@")[-1]:
             email_candidate = f_excerpt.strip()
             
        if email_candidate:
             domain_ctx = check_email_domain(email_candidate)
             if domain_ctx:
                 metadata["domain"] = domain_ctx["domain"]
                 metadata["domain_type"] = domain_ctx["domain_type"]
                 if domain_ctx["domain_type"] in ["disposable", "breached_org"]:
                      labels.append(OSINT_LABELS["HIGH_RISK_DOMAIN_CONTEXT"])

        # 4. Public exposure surface
        # If the finding was found in a JS file
        if f_source and f_source.endswith(".js"):
             labels.append(OSINT_LABELS["PUBLICLY_EXPOSED_ARTIFACT"])
             if not metadata.get("exposure_surface"):
                 metadata["exposure_surface"] = "external_js"
                 
        # 5. Cloud / CDN fingerprinting
        # Cloud fingerprint should be a label only if exposure surface is public
        if global_providers and metadata.get("exposure_surface"):
            labels.append(OSINT_LABELS["INFRASTRUCTURE_FINGERPRINT_EXPOSED"])
            metadata["cloud_provider"] = ", ".join(global_providers)

        # 6. Secret reuse indicator
        if finding.get("metadata", {}).get("reuse_count", 0) > 1:
             labels.append(OSINT_LABELS["SECRET_REUSE_DETECTED"])

        # Finalize
        if not labels:
            labels.append(OSINT_LABELS["NO_OSINT_SIGNAL"])
            
        # Clean metadata
        metadata = {k: v for k, v in metadata.items() if v is not None}

        finding["osint"] = {
            "labels": list(dict.fromkeys(labels)), # Ordered dedupe
            "metadata": metadata
        }

    return findings
