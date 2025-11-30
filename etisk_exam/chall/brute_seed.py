#!/usr/bin/env python3
"""
Known Plaintext Attack for DES-CBC

We know:
- Plaintext starts with "flag{" (at least 5 bytes known)
- We have IV and first ciphertext block
- DES has only 56-bit effective keyspace (2^56 keys)

For CBC mode: C1 = E_K(P1 ⊕ IV)
If we know P1 and have C1, we need to find K

However, brute forcing 2^56 is still too large.
But if the key is derived from a weak seed/LCG, we can brute force the SEED space instead.

The seed is likely a 32-bit value or less.
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad
import hashlib

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return data[:8], data[8:]

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

def try_decrypt(key, iv, ciphertext):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        return plaintext if b'flag{' in plaintext else None
    except:
        return None

iv, ct = read_encrypted_file("encrypted.flag")
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ct.hex()}\n")

# Brute force seed space (32-bit)
print("[*] Brute forcing 32-bit seed space for LCG...")
print("[*] This will test 2^32 ≈ 4 billion seeds...")
print("[*] Testing in chunks...\n")

# Test in reasonable chunks
chunk_size = 1000000
for chunk_start in range(0, 0x100000000, chunk_size):  # Full 32-bit space
    chunk_end = min(chunk_start + chunk_size, 0x100000000)
    
    if chunk_start % (chunk_size * 10) == 0:
        progress = (chunk_start / 0x100000000) * 100
        print(f"[*] Progress: {progress:.2f}% (seed range: {chunk_start}-{chunk_end})")
    
    for seed in range(chunk_start, chunk_end):
        key = _init_key(seed)
        plaintext = try_decrypt(key, iv, ct)
        if plaintext:
            print(f"\n{'='*60}")
            print(f"[+] FOUND!")
            print(f"[+] Seed: {seed} (0x{seed:08x})")
            print(f"[+] Key: {key.hex()}")
            print(f"[+] Flag: {plaintext.decode()}")
            print(f"{'='*60}")
            exit(0)
    
    # Early exit for testing
    if chunk_end >= 10000000:  # Stop after testing first 10 million
        print("\n[*] Tested first 10 million seeds, no match.")
        print("[*] Full brute force would take hours. The key generation might not use _init_key.")
        break

print("\n[-] Seed not found in tested range.")
