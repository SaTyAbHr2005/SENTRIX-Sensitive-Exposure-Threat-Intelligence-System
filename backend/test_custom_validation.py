
import sys
import os
import secrets
import string

# Add backend to path so we can import app
backend_path = os.path.join(os.getcwd(), 'backend')
if backend_path not in sys.path:
    sys.path.append(backend_path)

try:
    from app.utils.validation_analyzer import ValidationAnalyzer
except ImportError as e:
    # Try different path if script is run from backend dir
    sys.path.append(os.path.join(os.getcwd()))
    from app.utils.validation_analyzer import ValidationAnalyzer

def generate_random_api_key(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def test():
    print("Initializing ValidationAnalyzer for Custom Test...")
    analyzer = ValidationAnalyzer()

    # User requested test email
    test_email = "selfsudy123@gmail.com"
    
    # Generate some random API keys
    # 1. Standard looking strong key
    random_key_1 = generate_random_api_key(32)
    # 2. Longer key
    random_key_2 = generate_random_api_key(64)
    # 3. Short/Weak key
    random_key_weak = "12345678" 
    # 4. Patterned key (prefix often seen in real keys)
    random_key_prefixed = "sk_test_" + generate_random_api_key(24)

    test_cases = [
        {"secret": test_email, "type": "email", "desc": "User Test Email"},
        {"secret": random_key_1, "type": "api_key", "desc": "Random Strong Key (32 chars)"},
        {"secret": random_key_2, "type": "api_key", "desc": "Random Strong Key (64 chars)"},
        {"secret": random_key_weak, "type": "api_key", "desc": "Weak/Short Key"},
        {"secret": random_key_prefixed, "type": "api_key", "desc": "Prefixed API Key (sk_test_...)"},
    ]

    print("\n--- Running Custom Validation Tests ---\n")
    for case in test_cases:
        print(f"Test: {case['desc']}")
        print(f"Input: {case['secret']}")
        
        # Analyze
        result = analyzer.analyze(case['secret'], case['type'])
        
        # Output
        print(f"Label:      {result['label'].upper()}")
        print(f"Confidence: {result['confidence']}/100")
        print(f"Reason:     {result['reason']}")
        print(f"Metadata:   {result['metadata']}")
        print("-" * 50)

if __name__ == "__main__":
    test()
