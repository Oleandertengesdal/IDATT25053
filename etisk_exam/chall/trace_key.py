#!/usr/bin/env python3
"""
Trace what key the ransomware ACTUALLY generates
"""
import sys
sys.path.insert(0, '/Users/oleandertengesdal/Documents/GitHub/IDATT25053/etisk_exam/chall')

# Import and patch the code to see what key it uses
import chall
import hashlib

# Monkey patch to capture the key
original_des_new = None
captured_key = None

def patched_des_new(key, mode, iv=None):
    global captured_key
    captured_key = key
    print(f"[*] DES.new called with key: {key.hex()}")
    from Crypto.Cipher import DES
    if iv:
        return DES.new(key, mode, iv)
    return DES.new(key, mode)

# Apply patch
from Crypto.Cipher import DES as DES_module  
DES_module.new = patched_des_new

# Now try to see what key is generated
print("[*] Simulating key generation...")
print(f"[*] USE_ENV_ENTROPY = {chall.USE_ENV_ENTROPY}")
print(f"[*] USE_BUILD_TIME_KEY = {chall.USE_BUILD_TIME_KEY}")
print(f"[*] USE_PBKDF2 = {chall.USE_PBKDF2}")

key = chall._select_key_source()
print(f"\n[+] Generated key: {key.hex()}")
print(f"[+] Key length: {len(key)} bytes")

# Check what the environment entropy actually is
entropy = chall._get_system_fingerprint()
print(f"\n[*] System fingerprint: {entropy[:100]}...")
print(f"[*] Fingerprint length: {len(entropy)} bytes")

env_key = hashlib.shake_256(entropy).digest(8)
print(f"[*] Environment-derived key would be: {env_key.hex()}")
