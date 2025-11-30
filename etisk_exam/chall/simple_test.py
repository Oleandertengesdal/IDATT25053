#!/usr/bin/env python3
"""
WanaSmile - Simple test of all possible key functions
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib
import time

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    iv = data[:8]
    ciphertext = data[8:]
    return iv, ciphertext

def try_decrypt(key, iv, ciphertext, key_name):
    """Try to decrypt with a given key"""
    try:
        print(f"[*] Trying {key_name}: {key.hex()}")
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, 8)
        if b'flag{' in plaintext:
            print(f"[+] SUCCESS with {key_name}!")
            print(f"[+] Flag: {plaintext.decode()}")
            return True
    except Exception as e:
        print(f"    Failed: {e}")
    return False

# Read encrypted file
iv, ciphertext = read_encrypted_file("encrypted.flag")
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ciphertext.hex()}\n")

# Try 1: Fallback key
key = hashlib.md5(b"2025_des_ctf").digest()[:8]
if try_decrypt(key, iv, ciphertext, "Fallback key (_fallback_key_v2)"):
    exit(0)

# Try 2: _init_key with time//60 around attack time (Dec 11, 2024 03:14 UTC)
# 03:14 UTC = 1733889240 seconds since epoch
# time // 60 = 28898154
attack_time = 1733889240
for offset in range(-10, 10):
    seed = (attack_time + offset*60) // 60
    # Implement _init_key
    a = 214013
    c = 2531011
    m = 2**31
    key_bytes = b''
    state = seed
    for _ in range(8):
        state = (a * state + c) % m
        key_bytes += (state >> 16).to_bytes(2, 'big')
    key = key_bytes[:8]
    
    if try_decrypt(key, iv, ciphertext, f"_init_key(seed={seed})"):
        exit(0)

# Try 3: Current time when we decrypt (maybe it's actually time-based?)
for offset in range(-60, 60):
    seed = int(time.time() // 60) + offset
    a = 214013
    c = 2531011
    m = 2**31
    key_bytes = b''
    state = seed
    for _ in range(8):
        state = (a * state + c) % m
        key_bytes += (state >> 16).to_bytes(2, 'big')
    key = key_bytes[:8]
    
    if try_decrypt(key, iv, ciphertext, f"_init_key(current-{offset}min)"):
        exit(0)

print("\n[-] None of the keys worked!")
