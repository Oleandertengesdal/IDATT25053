#!/usr/bin/env python3
"""
WanaSmile Ransomware Decryption Tool
Exploits the critical cryptographic flaw in key generation
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib

def derive_key_from_build_timestamp():
    """
    VULNERABILITY: The ransomware uses a hardcoded build timestamp
    as the seed for key generation via a Linear Congruential Generator.
    
    This makes the key completely deterministic and predictable!
    """
    build_ts = 1733961600  # Hardcoded in the ransomware
    state = build_ts
    key_bytes = b''
    
    # LCG parameters (same as in chall.py)
    # The original code generates 8 bytes by creating 2-byte chunks
    for _ in range(8):
        state = (state * 1103515245 + 12345) & 0x7fffffff
        key_bytes += (state >> 16).to_bytes(2, 'big')
    
    return key_bytes[:8]  # Take first 8 bytes for DES key

def decrypt_file(ciphertext_file, plaintext_file):
    """
    Decrypt the ransomware-encrypted file
    """
    # Recreate the EXACT same key the ransomware used
    key = derive_key_from_build_timestamp()
    
    print(f"[*] Derived DES key: {key.hex()}")
    print(f"[*] Key length: {len(key)} bytes")
    
    # Read encrypted file
    with open(ciphertext_file, 'rb') as f:
        data = f.read()
    
    print(f"[*] Encrypted file size: {len(data)} bytes")
    
    # Extract IV (first 8 bytes) and ciphertext
    iv = data[:8]
    ciphertext = data[8:]
    
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Ciphertext size: {len(ciphertext)} bytes")
    
    # Decrypt using DES-CBC (same mode as encryption)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Remove PKCS7 padding
    plaintext = unpad(padded_plaintext, 8)
    
    # Save decrypted file
    with open(plaintext_file, 'wb') as f:
        f.write(plaintext)
    
    print(f"[+] Successfully decrypted to: {plaintext_file}")
    print(f"[+] Decrypted content:\n{plaintext.decode('utf-8', errors='ignore')}")
    
    return plaintext

if __name__ == "__main__":
    print("="*60)
    print("WanaSmile Ransomware Decryption Tool")
    print("="*60)
    print()
    print("VULNERABILITY ANALYSIS:")
    print("- Ransomware uses DES-CBC encryption")
    print("- Key derived from hardcoded BUILD_TIME timestamp")
    print("- LCG with fixed seed = completely deterministic key")
    print("- No randomness, no entropy, no security!")
    print()
    print("="*60)
    print()
    
    try:
        plaintext = decrypt_file("encrypted.flag", "flag.txt")
        print()
        print("="*60)
        print("SUCCESS! Flag recovered.")
        print("="*60)
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        import traceback
        traceback.print_exc()
