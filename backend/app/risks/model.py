"""
ML-based Risk Refinement for Module 5.
Uses a RandomForestClassifier to predict risk severity based on feature vectors.
Includes synthetic data generation for offline training.
"""
import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

class RiskClassifier:
    def __init__(self):
        self.model = None
        self.le = LabelEncoder()
        self.classes = ["Low", "Medium", "High"]
        self.feature_names = [
            "is_valid", "is_plausible", "category_score", "entropy", 
            "length", "is_public", "is_admin", "has_domain"
        ]
        
    def _extract_features(self, finding):
        """
        Converts a finding dictionary into a numerical feature vector.
        Vector Schema:
        [
            is_valid (0/1),
            is_plausible (0/1),
            category_score (0=Gen, 1=High, 2=Crit),
            entropy (float),
            secret_length (int),
            is_public (0/1),
            is_admin (0/1),
            has_domain_context (0/1)
        ]
        """
        validation = finding.get("validation", {})
        osint = finding.get("osint", {})
        labels = osint.get("labels", [])
        
        # 1. Validity
        val_status = validation.get("validity", "unknown").lower()
        is_valid = 1 if val_status in ["active", "confirmed"] else 0
        is_plausible = 1 if val_status == "plausible" else 0
        
        # 2. Category Score
        cat = finding.get("category", "").upper().replace("_", "").replace(" ", "")
        crit_cats = ["AWS", "GCP", "AZURE", "PRIVATEKEY", "SLACK", "STRIPE"]
        high_cats = ["APIKEY", "JWT", "DB", "ACCESSKEY", "SECRET"]
        
        if any(c in cat for c in crit_cats):
            cat_score = 2
        elif any(c in cat for c in high_cats):
            cat_score = 1
        else:
            cat_score = 0
            
        # 3. Numeric Meta
        entropy = validation.get("entropy", 3.0) # default avg entropy
        # Length normalized (capped at 100 to avoid skew)
        length = len(finding.get("excerpt", "")) 
        length = min(length, 100)
        
        # 4. OSINT Booleans
        is_public = 1 if "PUBLICLY_EXPOSED_ARTIFACT" in labels else 0
        is_admin = 1 if "EXPOSED_ADMIN_PATH" in labels else 0
        has_domain = 1 if "HIGH_RISK_DOMAIN_CONTEXT" in labels else 0
        
        return [
            is_valid, 
            is_plausible, 
            cat_score, 
            entropy, 
            length, 
            is_public, 
            is_admin, 
            has_domain
        ]

    def train_synthetic(self):
        """
        Generates synthetic data and trains the model.
        This ensures the ML component is genuinely used even without a massive historical dataset.
        """
        X = []
        y = []
        
        # Generate 1000 samples
        # Logic: 
        # - Valid + Critical = High
        # - Valid + Generic = Medium/High
        # - Invalid + Generic = Low
        # - Plausible + Public = Medium
        
        np.random.seed(42)
        
        for _ in range(1000):
            # Randomize features
            is_valid = np.random.choice([0, 1], p=[0.7, 0.3])
            # If Valid, cannot be just Plausible (mutually exclusive usually, but for feats we treat separate)
            is_plausible = 0 if is_valid else np.random.choice([0, 1])
            
            cat_score = np.random.choice([0, 1, 2], p=[0.5, 0.3, 0.2])
            entropy = np.random.normal(4.5, 1.0)
            length = np.random.normal(40, 15)
            
            is_public = np.random.choice([0, 1])
            is_admin = np.random.choice([0, 1])
            has_domain = np.random.choice([0, 1])
            
            # Label Logic (Simulate Ground Truth)
            score = 0
            if is_valid: score += 50
            if is_plausible: score += 20
            if cat_score == 2: score += 30
            elif cat_score == 1: score += 15
            if is_public: score += 15
            if is_admin: score += 10
            
            # Noise
            score += np.random.normal(0, 5)
            
            label = "Low"
            if score > 70: label = "High"
            elif score > 35: label = "Medium"
            
            X.append([is_valid, is_plausible, cat_score, entropy, length, is_public, is_admin, has_domain])
            y.append(label)
            
        # Train
        self.model = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
        self.model.fit(X, y)
        
        # Save
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)
            
        print("ML Model trained on synthetic data.")

    def load(self):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
        else:
            print("Model not found. Training new one...")
            self.train_synthetic()

    def predict(self, finding):
        if not self.model:
            self.load()
            
        features = np.array(self._extract_features(finding)).reshape(1, -1)
        
        # Predict Class
        severity = self.model.predict(features)[0]
        
        # Predict Proba (Use this for granular scoring refinement)
        # Classes are usually sorted lexicographically: High, Low, Medium (Check self.model.classes_)
        # But we want a "Risk Score" out of 100.
        # We can map class probs to a weighted score.
        probs = self.model.predict_proba(features)[0]
        classes = self.model.classes_ 
        
        # Calculate Weighted ML Score
        # Weights: Low=10, Medium=50, High=90
        score_map = {"Low": 10, "Medium": 50, "High": 90}
        ml_score = 0
        for cls, prob in zip(classes, probs):
            ml_score += score_map.get(cls, 0) * prob
            
        # Feature Importance (Explainability)
        top_features = []
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1]
            for i in range(min(3, len(indices))): # Top 3 features
                idx = indices[i]
                top_features.append({
                    "feature": self.feature_names[idx],
                    "importance": float(importances[idx])
                })
            
        return ml_score, severity, top_features

