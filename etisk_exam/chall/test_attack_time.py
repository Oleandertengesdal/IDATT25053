#!/usr/bin/env python3
"""
Test with exact attack timestamps
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    iv = data[:8]
    ciphertext = data[8:]
    return iv, ciphertext

def try_decrypt(key, iv, ciphertext, key_name):
    """Try to decrypt with a given key"""
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, 8)
        if b'flag{' in plaintext or b'FLAG' in plaintext:
            print(f"\n{'='*60}")
            print(f"[+] SUCCESS with {key_name}!")
            print(f"[+] Key: {key.hex()}")
            print(f"[+] Flag: {plaintext.decode()}")
            print(f"{'='*60}")
            return True
    except Exception as e:
        pass
    return False

def _init_key(seed):
    """LCG key derivation"""
    a = 214013
    c = 2531011
    m = 2**31
    key_bytes = b''
    state = seed
    for _ in range(8):
        state = (a * state + c) % m
        key_bytes += (state >> 16).to_bytes(2, 'big')
    return key_bytes[:8]

# Read encrypted file
iv, ciphertext = read_encrypted_file("encrypted.flag")

# Nov 14, 2024 at 03:14:00 UTC
base_timestamp = 1731554040
base_seed = base_timestamp // 60  # 28859234

print(f"[*] Testing Nov 14, 2024 03:14 UTC timestamps...")
print(f"[*] Base timestamp: {base_timestamp}")
print(f"[*] Base seed (time//60): {base_seed}\n")

# Try exact minute and surrounding minutes
for offset in range(-120, 120):  # ±2 hours
    seed = base_seed + offset
    key = _init_key(seed)
    if try_decrypt(key, iv, ciphertext, f"seed={seed} (offset={offset}min from 03:14)"):
        exit(0)

# Try exact timestamps (not divided by 60)
print("\n[*] Trying exact timestamps (not // 60)...")
for offset in range(-7200, 7200):  # ±2 hours in seconds
    seed = base_timestamp + offset
    key = _init_key(seed)
    if offset % 300 == 0:  # Progress every 5 minutes
        print(f"[*] Trying timestamp {seed}...")
    if try_decrypt(key, iv, ciphertext, f"seed={seed} (timestamp+{offset}s)"):
        exit(0)

print("\n[-] No matches found around the attack time.")
