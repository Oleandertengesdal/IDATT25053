#!/usr/bin/env python3
"""
Test with very simple seeds - maybe the bug is using a trivial/default seed
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib

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
    except:
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
print(f"IV: {iv.hex()}")
print(f"Ciphertext length: {len(ciphertext)} bytes\n")

# Try simple seeds that might be used due to "rushed" development
print("[*] Trying trivial seeds...")
trivial_seeds = [
    0, 1, 2, 3, 4, 5, 10, 100, 1000,
    1337, 31337,  # leet
    12345, 123456, 1234567,
    42,  # answer to everything
    0xDEADBEEF, 0xCAFEBABE, 0x1337CAFE,
    2024, 2025,  # years
]

for seed in trivial_seeds:
    key = _init_key(seed)
    if try_decrypt(key, iv, ciphertext, f"_init_key({seed})"):
        exit(0)

# Maybe the BUILD_ID is used as seed?
print("\n[*] Trying BUILD_ID as seed...")
BUILD_ID = 0x1337CAFEBABE
key = _init_key(BUILD_ID)
if try_decrypt(key, iv, ciphertext, f"_init_key(BUILD_ID={hex(BUILD_ID)})"):
    exit(0)

# Try using 0 which would happen if time.time() failed somehow
print("\n[*] Trying seed=0 scenarios...")
key = _init_key(0)
if try_decrypt(key, iv, ciphertext, "_init_key(0)"):
    exit(0)

# What if the attacker didn't use any of the complex functions
# and just hardcoded a weak key?
print("\n[*] Trying weak hardcoded keys...")
weak_keys = [
    b'\x00' * 8,
    b'\x01' * 8,
    b'\xff' * 8,
    b'12345678',
    b'password',
    b'AAAAAAAA',
    hashlib.md5(b"password").digest()[:8],
    hashlib.md5(b"12345678").digest()[:8],
    hashlib.md5(b"admin").digest()[:8],
]

for key in weak_keys:
    if try_decrypt(key, iv, ciphertext, f"Weak key: {key.hex()}"):
        exit(0)

print("\n[-] No simple seeds worked. Need to investigate further...")
