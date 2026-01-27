"""
Rule-based Security Enforcement for Module 5.
Defines hard security rules that serve as the baseline for risk assessment.
"""

def calculate_base_score(finding):
    """
    Calculates a deterministic risk score based on static security rules.
    
    Args:
        finding (dict): The finding object containing detection, validation, and OSINT data.
        
    Returns:
        tuple: (base_score (0-100), severity (str), risk_factors (list))
    """
    score = 0
    factors = []
    
    # --- Feature Extraction Helpers ---
    category = finding.get("category", "").upper()
    validation = finding.get("validation", {})
    osint = finding.get("osint", {})
    osint_labels = osint.get("labels", [])
    
    # --- Rule 1: Validity (The most critical factor) ---
    # Validation module should provide a 'validity' status
    validity = validation.get("validity", "unknown").lower()
    
    if validity == "active" or validity == "confirmed":
        score += 60
        factors.append("Secret is confirmed ACTIVE/VALID")
    elif validity == "plausible":
        score += 30
        factors.append("Secret structure is PLAUSIBLE")
    else:
        # Invalid secrets start low, but context might raise it
        score += 0
        
    # --- Rule 2: Secret Category Impact ---
    # Normalize category for matching (remove special chars)
    cat_norm = category.replace("_", "").replace(" ", "")
    
    CRITICAL_cats = ["AWS", "GCP", "AZURE", "SLACK", "STRIPE", "PRIVATEKEY"]
    HIGH_cats = ["DBPASSWORD", "APIKEY", "JWT", "ACCESSKEY", "SECRET"]
    
    if any(c in cat_norm for c in CRITICAL_cats):
        score += 25
        factors.append(f"Critical Secret Type: {category}")
    elif any(c in cat_norm for c in HIGH_cats):
        score += 15
        factors.append(f"High-Value Secret Type: {category}")
    else:
        score += 5
        
    # --- Rule 3: Exposure Context (OSINT) ---
    if "PUBLICLY_EXPOSED_ARTIFACT" in osint_labels:
        score += 10
        factors.append("Found in public JS file (External Exposure)")
    
    if "EXPOSED_ADMIN_PATH" in osint_labels:
        score += 10
        factors.append("Found in Admin/Config path")
        
    if "HIGH_RISK_DOMAIN_CONTEXT" in osint_labels:
        score += 5
        factors.append("Associated with high-risk domain")

    # --- Rule 4: Heuristics ---
    # Penalty for generic/weak secrets if not validated
    if "generic" in category.lower() and validity != "confirmed":
        score = min(score, 40) # Cap generic at Medium unless validated
    
    # --- Scoring Normalization ---
    # Ensure baseline risk for any detection is at least 10
    score = min(100, max(10, score))
    
    # --- Severity Mapping ---
    if score >= 80:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"  # Score < 40 is Low (usually Info/Noise)
        
    return score, severity, factors
