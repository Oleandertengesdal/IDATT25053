#!/usr/bin/env python3
"""
WanaSmile Ransomware Decryption - Multiple Attack Strategies
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad
import hashlib
import os
import itertools

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    iv = data[:8]
    ciphertext = data[8:]
    return iv, ciphertext

def try_decrypt(key, iv, ciphertext):
    """Try to decrypt with a given key"""
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, 8)
        return plaintext
    except:
        return None

def derive_key_from_build_timestamp(timestamp):
    """Derive key from build timestamp"""
    state = timestamp
    key_bytes = b''
    for _ in range(8):
        state = (state * 1103515245 + 12345) & 0x7fffffff
        key_bytes += (state >> 16).to_bytes(2, 'big')
    return key_bytes[:8]

def derive_key_from_environment(pid, uid, hostname="", shell="", path="", tzname="UTC"):
    """Derive key from environment variables"""
    sources = [
        path,
        shell,
        str(pid),
        str(uid),
        hostname,
        tzname
    ]
    entropy = "".join(sources).encode()
    return hashlib.shake_256(entropy).digest(8)

def brute_force_build_timestamp(iv, ciphertext, start_time, end_time):
    """Brute force build timestamps"""
    print(f"[*] Brute forcing timestamps from {start_time} to {end_time}...")
    for timestamp in range(start_time, end_time):
        if timestamp % 10000 == 0:
            print(f"[*] Trying timestamp: {timestamp}")
        key = derive_key_from_build_timestamp(timestamp)
        plaintext = try_decrypt(key, iv, ciphertext)
        if plaintext and b'flag{' in plaintext:
            return key, plaintext
    return None, None

def brute_force_pid(iv, ciphertext, uid, max_pid=65536):
    """Brute force PIDs (most likely attack vector for rushed ransomware)"""
    print(f"[*] Brute forcing PIDs (UID={uid})...")
    
    # Common hostnames on CTF servers
    hostnames = ["localhost", "ctf", "server", "ubuntu", "debian", ""]
    shells = ["/bin/bash", "/bin/sh", "/bin/zsh", ""]
    paths = ["", "/usr/local/bin:/usr/bin:/bin"]
    tznames = ["UTC", "EST", "PST", ""]
    
    count = 0
    for pid in range(1, max_pid):
        for hostname in hostnames:
            for shell in shells:
                for path in paths:
                    for tzname in tznames:
                        count += 1
                        if count % 1000 == 0:
                            print(f"[*] Tried {count} combinations (PID={pid})...")
                        
                        key = derive_key_from_environment(pid, uid, hostname, shell, path, tzname)
                        plaintext = try_decrypt(key, iv, ciphertext)
                        if plaintext and b'flag{' in plaintext:
                            print(f"[+] FOUND! PID={pid}, hostname={hostname}, shell={shell}, tzname={tzname}")
                            return key, plaintext
    return None, None

def known_plaintext_key_recovery(iv, ciphertext, known_plaintext=b"flag{"):
    """
    Known plaintext attack for DES
    Since we know the flag starts with "flag{", we can try to recover the key
    """
    print(f"[*] Known plaintext attack...")
    print(f"[*] Known plaintext: {known_plaintext}")
    
    # For DES-CBC, first block: C1 = E(P1 XOR IV)
    # We know P1 starts with "flag{"
    # We need to find the key K such that C1 = DES_K(P1 XOR IV)
    
    # This requires brute forcing 56-bit DES key space (too large)
    # But if key derivation is weak, we can brute force the seed instead
    
    return None, None

if __name__ == "__main__":
    print("="*60)
    print("WanaSmile Ransomware Decryption - Advanced Mode")
    print("="*60)
    print()
    
    iv, ciphertext = read_encrypted_file("encrypted.flag")
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Ciphertext: {ciphertext.hex()}")
    print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
    print()
    
    # Strategy 1: Try the hardcoded build timestamp
    print("[1] Trying hardcoded BUILD_TIME...")
    key = derive_key_from_build_timestamp(1733961600)
    print(f"    Key: {key.hex()}")
    plaintext = try_decrypt(key, iv, ciphertext)
    if plaintext and b'flag{' in plaintext:
        print(f"[+] SUCCESS! Flag: {plaintext.decode()}")
        exit(0)
    print("    ✗ Failed\n")
    
    # Strategy 2: Brute force common PIDs with current UID
    print("[2] Brute forcing PIDs with current UID...")
    uid = os.getuid()
    print(f"    Current UID: {uid}")
    key, plaintext = brute_force_pid(iv, ciphertext, uid, max_pid=10000)
    if plaintext:
        print(f"[+] SUCCESS! Flag: {plaintext.decode()}")
        print(f"[+] Key: {key.hex()}")
        exit(0)
    print("    ✗ Failed\n")
    
    # Strategy 3: Brute force nearby timestamps
    print("[3] Brute forcing timestamps around December 2024...")
    key, plaintext = brute_force_build_timestamp(iv, ciphertext, 1733961600-86400, 1733961600+86400)
    if plaintext:
        print(f"[+] SUCCESS! Flag: {plaintext.decode()}")
        print(f"[+] Key: {key.hex()}")
        exit(0)
    print("    ✗ Failed\n")
    
    print("[-] All strategies failed. The key generation might use different parameters.")
