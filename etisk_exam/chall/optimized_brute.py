#!/usr/bin/env python3
"""
Optimized environment entropy brute force
Focus on most likely server configurations
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib
import itertools

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return data[:8], data[8:]

def try_decrypt(key, iv, ciphertext):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        return plaintext if b'flag{' in plaintext else None
    except:
        return None

def derive_key_from_env(path, shell, pid, uid, hostname, tzname):
    sources = [path, shell, str(pid), str(uid), hostname, tzname]
    entropy = "".join(sources).encode()
    return hashlib.shake_256(entropy).digest(8)

iv, ct = read_encrypted_file("encrypted.flag")
print(f"IV: {iv.hex()}")
print(f"Ciphertext: {ct.hex()}\n")

# Most likely server configurations (prioritized)
configs = [
    # (path, shell, uid_range, hostname_list, tzname_list)
    # Empty/minimal configs (rushed deployment)
    ("", "", range(0, 100), ["", "localhost"], [""]),
    ("", "", range(100, 1001), ["", "localhost", "ctf"], ["", "UTC"]),
    
    # Standard Ubuntu/Debian paths
    ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "/bin/bash", range(0, 100), ["", "localhost", "ubuntu"], ["", "UTC"]),
    ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "/bin/sh", range(0, 100), ["", "localhost", "ctf", "server"], ["", "UTC"]),
    
    # More common configs
    ("/usr/local/bin:/usr/bin:/bin", "/bin/bash", range(1000, 1010), ["localhost", "ctf"], ["UTC"]),
    ("/usr/local/bin:/usr/bin:/bin", "/bin/sh", range(1000, 1010), ["localhost", "server"], ["UTC"]),
]

total_tested = 0
for config_idx, (path, shell, uid_range, hostnames, tznames) in enumerate(configs, 1):
    print(f"\n[*] Testing config {config_idx}/{len(configs)}")
    print(f"    PATH: '{path[:50]}...' SHELL: '{shell}'")
    print(f"    Testing UIDs: {uid_range.start}-{uid_range.stop-1}")
    print(f"    Hostnames: {hostnames}")
    print(f"    Timezones: {tznames}")
    
    config_count = 0
    for pid in range(1, 10001):  # PIDs 1-10000 (services typically have low PIDs)
        for uid in uid_range:
            for hostname in hostnames:
                for tzname in tznames:
                    config_count += 1
                    total_tested += 1
                    
                    if config_count % 50000 == 0:
                        print(f"    [{total_tested:,} total] Testing PID={pid}, UID={uid}...")
                    
                    key = derive_key_from_env(path, shell, pid, uid, hostname, tzname)
                    plaintext = try_decrypt(key, iv, ct)
                    
                    if plaintext:
                        print(f"\n{'='*60}")
                        print(f"[+] SUCCESS!")
                        print(f"{'='*60}")
                        print(f"PATH: '{path}'")
                        print(f"SHELL: '{shell}'")
                        print(f"PID: {pid}")
                        print(f"UID: {uid}")
                        print(f"HOSTNAME: '{hostname}'")
                        print(f"TZNAME: '{tzname}'")
                        print(f"Key: {key.hex()}")
                        print(f"Flag: {plaintext.decode()}")
                        print(f"{'='*60}")
                        exit(0)

print(f"\n[-] Tested {total_tested:,} combinations without success.")
print("[*] The environment might have different values.")
print("[*] Consider expanding the search space or trying different attack vectors.")
