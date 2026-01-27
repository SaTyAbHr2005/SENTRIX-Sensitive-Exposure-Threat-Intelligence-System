
import math
import collections
import json
import base64
import re
import socket
import logging

try:
    import dns.resolver as dns_resolver
    DNS_AVAILABLE = True
except (ImportError, AttributeError):
    DNS_AVAILABLE = False

logger = logging.getLogger(__name__)

class ValidationAnalyzer:
    """
    Module 3: Validation & Exploitability Analyzer
    Analyzes detected secrets for structural validity, plausibility, and entropy.
    Offline only.
    """

    def __init__(self):
        # Configuration for length thresholds (R13)
        self.MIN_LENGTHS = {
            "jwt": 32,
            "api_key": 16,
            "oauth": 20,
            "private_key": 64,  # usually much longer (PEM)
            "generic": 10
        }
        # Entropies typical for random secrets (bits per char)
        self.ENTROPY_THRESHOLDS = {
            "high": 4.5,
            "medium": 3.5,
            "low": 2.5
        }

    def analyze(self, secret_candidate: str, secret_type: str = "generic") -> dict:
        """
        Main entry point for validation.
        :param secret_candidate: The string to analyze.
        :param secret_type: Expected type (jwt, api_key, email, private_key, generic, etc.)
        :return: Dict containing validation results.
        """
        if not secret_candidate:
            return self._result("invalid", 0, "Empty secret")

        # 1. Structural/Type-specific Validation
        secret_type = secret_type.lower()
        
        # Dispatch based on type
        if "jwt" in secret_type or self._looks_like_jwt(secret_candidate):
            return self._validate_jwt(secret_candidate)
        
        if "email" in secret_type or "@" in secret_candidate:
             # Basic check if it looks like an email
             if re.match(r"[^@]+@[^@]+\.[^@]+", secret_candidate):
                 return self._validate_email(secret_candidate)

        # 2. General Plausibility Checks (R11, R13) for API keys/Tokens
        return self._validate_generic_token(secret_candidate, secret_type)

    def _result(self, label: str, confidence: int, reason: str, metadata: dict = None):
        return {
            "label": label,  # 'valid', 'likely', 'invalid'
            "confidence": min(100, max(0, confidence)),
            "reason": reason,
            "metadata": metadata or {}
        }

    # --- R10: JWT Structural Validation ---
    def _looks_like_jwt(self, text: str) -> bool:
        # 2 periods, 3 parts
        return text.count('.') == 2 and len(text) > 30

    def _validate_jwt(self, token: str) -> dict:
        parts = token.split('.')
        if len(parts) != 3:
            return self._result("invalid", 100, "Malformatted JWT: Incorrect number of segments")

        header_b64, payload_b64, signature_b64 = parts
        
        # Check empty parts
        if not header_b64 or not payload_b64:
             return self._result("invalid", 100, "Malformatted JWT: Empty header or payload")

        metadata = {}
        
        # Validate JSON decoding of Header and Payload
        try:
            header = self._safe_b64_decode_json(header_b64)
            if not header or not isinstance(header, dict):
                 return self._result("invalid", 100, "JWT Header is not a valid JSON object")
            
            payload = self._safe_b64_decode_json(payload_b64)
            if not payload or not isinstance(payload, dict):
                 return self._result("invalid", 100, "JWT Payload is not a valid JSON object")

            metadata['header'] = header
            metadata['claims'] = payload  # 'payload' is claims
            
        except ValueError:
            return self._result("invalid", 100, "JWT segments are not valid Base64URL or JSON")

        # Check for standard claims (R11 confidence boost)
        std_claims = {'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti'}
        detected_claims = [k for k in payload.keys() if k in std_claims]
        
        # Confidence logic
        # Structurally valid JSON in header/payload is a strong signal.
        confidence = 85 
        if detected_claims:
            confidence += len(detected_claims) * 2  # Boost by 2 per claim
            metadata['standard_claims'] = detected_claims
        
        # R13: Entropy check on signature (should be high entropy)
        sig_entropy = self._shannon_entropy(signature_b64)
        metadata['signature_entropy'] = sig_entropy
        
        if sig_entropy < 3.0: 
            confidence -= 20 # Suspiciously low entropy for a signature
            
        if confidence > 95: confidence = 95 # Cap since we can't verify crypto offline

        return self._result("valid", confidence, "Structurally valid JWT", metadata)

    def _safe_b64_decode_json(self, s: str):
        # Normalize Base64URL to Base64
        s = s.replace('-', '+').replace('_', '/')
        # Pad
        s += '=' * (4 - len(s) % 4)
        try:
            decoded = base64.b64decode(s)
            # Try decode string as UTF-8 then JSON
            return json.loads(decoded.decode('utf-8'))
        except Exception:
            return None

    # --- R12: Email Domain DNS Validation ---
    def _validate_email(self, email: str) -> dict:
        parts = email.split('@')
        if len(parts) != 2:
            return self._result("invalid", 100, "Invalid email format")
            
        domain = parts[1]
        
        if not DNS_AVAILABLE:
            return self._result("likely", 50, "Email structure valid (DNS check skipped)", {"domain": domain})

        try:
            # Check MX
            try:
                mx = dns_resolver.resolve(domain, 'MX')
                if mx:
                    return self._result("likely", 90, f"Valid MX records for {domain}", {"domain": domain, "mx_found": True})
            except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN):
                # Try A record fallback
                try:
                    a = dns_resolver.resolve(domain, 'A')
                    if a:
                        return self._result("likely", 70, f"No MX but valid A record for {domain}", {"domain": domain, "a_found": True})
                except Exception:
                    pass
            except Exception:
                 pass
                 
            # If we are here, DNS failed
            return self._result("invalid", 90, f"Domain {domain} has no MX or A records", {"domain": domain})

        except Exception as e:
            # DNS timeout etc
            return self._result("likely", 40, f"DNS check failed/timeout: {str(e)}", {"domain": domain})

    # --- R11 & R13: Generic/Base64/Entropy ---
    def _validate_generic_token(self, token: str, label: str) -> dict:
        length = len(token)
        entropy = self._shannon_entropy(token)
        
        metadata = {
            "length": length,
            "entropy": round(entropy, 2)
        }

        # Length Check
        min_len = self.MIN_LENGTHS.get(label, self.MIN_LENGTHS["generic"])
        if length < min_len:
            return self._result("invalid", 90, f"Token too short (len={length}, min={min_len})", metadata)
            
        # R11: Base64 Plausibility
        # If it looks like base64, try to decode and see if it is structure
        if re.match(r'^[A-Za-z0-9+/=]+$', token) and length % 4 == 0:
            try:
                decoded = base64.b64decode(token)
                # content check
                if b'{' in decoded and b'}' in decoded:
                    # Might be JSON
                    try:
                        obj = json.loads(decoded.decode('utf-8'))
                        if isinstance(obj, (dict, list)):
                             metadata['decoded_content'] = "json"
                             return self._result("valid", 80, "Base64 decoded to valid JSON", metadata)
                    except:
                        pass
                
                # Check for printable chars ratio
                printable = sum(1 for c in decoded if 32 <= c <= 126)
                ratio = printable / len(decoded) if len(decoded) > 0 else 0
                metadata['decoded_printable_ratio'] = round(ratio, 2)
                
            except Exception:
                pass

        # Entropy Check
        # Generic keys often have high entropy.
        # If label suggests a 'key' or 'token'
        if entropy < self.ENTROPY_THRESHOLDS['low'] and length > 20: 
             # Long low-entropy string -> likely predictable or garbage
             return self._result("invalid", 80, "Entropy too low for secret material", metadata)
             
        if entropy > self.ENTROPY_THRESHOLDS['high']:
             return self._result("likely", 70, "High entropy string", metadata)

        return self._result("likely", 50, "Plausible length and chars", metadata)

    def _shannon_entropy(self, data: str) -> float:
        """Calculates Shannon entropy of string."""
        if not data:
            return 0
        counts = collections.Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log(p, 2)
        return entropy
