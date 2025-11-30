#!/usr/bin/env python3
"""
The key uses environment entropy with shake_256.
The flaw: on a CTF test server, environment variables are predictable!
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib

def read_encrypted_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return data[:8], data[8:]

def try_decrypt(key, iv, ciphertext, desc):
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)
        if b'flag{' in plaintext:
            print(f"\n{'='*60}")
            print(f"✓ SUCCESS: {desc}")
            print(f"Key: {key.hex()}")
            print(f"Flag: {plaintext.decode()}")
            print(f"{'='*60}")
            return True
    except:
        pass
    return False

def derive_key_from_env(path, shell, pid, uid, hostname, tzname):
    sources = [path, shell, str(pid), str(uid), hostname, tzname]
    entropy = "".join(sources).encode()
    return hashlib.shake_256(entropy).digest(8)

iv, ct = read_encrypted_file("encrypted.flag")

# Common server configurations
paths = [
    "",  # Empty if not set
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games",
]
shells = ["", "/bin/bash", "/bin/sh"]
uids = [0, 1000, 1001, 501, 502]  # root or common user UIDs  
hostnames = ["", "localhost", "ctf", "server", "ubuntu", "debian", "test"]
tznames = ["", "UTC"]

print(f"Testing {len(paths) * len(shells) * 1000 * len(uids) * len(hostnames) * len(tznames)} combinations...")
print("(This may take a moment)\n")

count = 0
for path in paths:
    for shell in shells:
        for pid in range(1, 1001):  # Low PIDs are common for services
            for uid in uids:
                for hostname in hostnames:
                    for tzname in tznames:
                        count += 1
                        if count % 10000 == 0:
                            print(f"[*] Tried {count} combinations...")
                        key = derive_key_from_env(path, shell, pid, uid, hostname, tzname)
                        if try_decrypt(key, iv, ct, f"PATH={path[:30]}..., SHELL={shell}, PID={pid}, UID={uid}, HOST={hostname}, TZ={tzname}"):
                            exit(0)

print(f"\n[-] Tried {count} combinations, no match found.")
print("The environment might have different values...")
