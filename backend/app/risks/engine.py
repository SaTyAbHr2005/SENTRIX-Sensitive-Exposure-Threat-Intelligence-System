"""
Risk Engine Module.
Orchestrates the fusion of Rule-based enforcement and ML-based refinement.
"""
from .rules import calculate_base_score
from .model import RiskClassifier

class RiskEngine:
    def __init__(self):
        self.classifier = RiskClassifier()
        # Ensure model is ready
        self.classifier.load()

    def assess_risk(self, findings):
        """
        Process a list of findings and attach risk assessments.
        """
        for finding in findings:
            # 1. Rule Entry
            rule_score, rule_severity, rule_factors = calculate_base_score(finding)
            
            # 2. ML Entry
            ml_score, ml_severity, ml_top_features = self.classifier.predict(finding)
            
            # 3. Fusion Logic
            # Constraint: ML is ADVISORY. It can refine (elevate) risk but cannot override hard rules.
            # To preserve safety and explainability, we BOUND the ML influence:
            # - ML cannot downgrade a rule score (Safety).
            # - ML cannot elevate a score by more than 20 points (Stability/conservative uplift).
            
            # bounded_ml_contribution = min(rule_score + 20, ml_score)
            # final_score = max(rule_score, bounded_ml_contribution)
            # Simplified:
            final_score = max(rule_score, min(rule_score + 20, ml_score))
            
            # Severity Hierarchy (Strictly Low/Medium/High)
            sev_map = {"Low": 1, "Medium": 2, "High": 3}
            r_val = sev_map.get(rule_severity, 1)
            m_val = sev_map.get(ml_severity, 1)
            
            # Determine Final Severity based on score thresholds to keep it consistent with score
            # (Instead of just maxing the labels, we largely trust the final_score)
            if final_score >= 80:
                final_severity = "High"
            elif final_score >= 40:
                final_severity = "Medium"
            else:
                final_severity = "Low"
            
            # Add ML factors for explainability if it influenced the score
            if final_score > rule_score:
                uplift = final_score - rule_score
                rule_factors.append(f"ML Analysis refined risk score (+{int(uplift)})")
            
            # 4. Attach Result
            finding["risk"] = {
                "score": int(final_score),
                "severity": final_severity,
                "factors": rule_factors,
                "ml_analysis": {
                    "predicted_severity": ml_severity,
                    "confidence_score": int(ml_score),
                    "model_used": "RandomForestClassifier (Ensemble)",
                    "top_features": ml_top_features
                }
            }
            
        return findings

# Singleton instance for easy import
risk_engine = RiskEngine()
