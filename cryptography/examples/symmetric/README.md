# Symmetric Encryption Examples

Modern symmetric encryption using AES (Advanced Encryption Standard).

## ⚠️ Important Notes

- **Use these patterns in production** (unlike historical ciphers!)
- Always use **AES-256-GCM** for new applications
- Never reuse nonces/IVs with the same key
- Use **authenticated encryption** (GCM) to prevent tampering
- Follow the examples carefully

## Prerequisites

Install required library:
```bash
pip install cryptography
```

## Contents

### 1. AES Modes of Operation (`aes_modes.py`)

**Demonstrates 4 modes:**
- **ECB** (Electronic Codebook) - ⚠️ INSECURE, educational only
- **CBC** (Cipher Block Chaining) - OK, but prefer GCM
- **CTR** (Counter Mode) - Good, but no authentication
- **GCM** (Galois/Counter Mode) - ✅ **RECOMMENDED**

**Run it:**
```bash
python aes_modes.py
```

**What you'll learn:**
- Why ECB exposes patterns (famous penguin example)
- How CBC chains blocks together
- How CTR turns block cipher into stream cipher
- Why GCM is best (authenticated encryption)
- Catastrophic nonce reuse in CTR
- Tamper detection with GCM

**Key demonstrations:**
1. ECB identical blocks problem
2. CBC random IV requirement
3. CTR nonce reuse attack
4. GCM tamper detection

### 2. Secure File Encryption (`secure_file_encryption.py`)

**Production-ready file encryption** using:
- **AES-256-GCM** (authenticated encryption)
- **PBKDF2** key derivation (600,000 iterations)
- **Proper salt/nonce handling**

**Run demonstration:**
```bash
python secure_file_encryption.py
```

**Use as command-line tool:**
```bash
# Encrypt
python secure_file_encryption.py encrypt secret.txt secret.enc
Enter password: ********

# Decrypt
python secure_file_encryption.py decrypt secret.enc decrypted.txt
Enter password: ********
```

**File format:**
```
[Salt (16 bytes)][Nonce (12 bytes)][Ciphertext + Authentication Tag]
```

**What you'll learn:**
- Password-based encryption
- Key derivation with PBKDF2
- Proper salt generation and storage
- Nonce management
- Authentication tag verification
- Tamper detection

## Quick Reference

### When to Use Each Mode

| Mode | Use Case | Security |
|------|----------|----------|
| **GCM** | **Everything** (default choice) | ✅ Best |
| CTR | High-performance bulk encryption (add HMAC!) | ✅ Good |
| CBC | Legacy systems (add HMAC!) | ⚠️ OK |
| ECB | **NEVER** | ❌ Insecure |

### AES Key Sizes

| Key Size | Security Level | Use Case |
|----------|----------------|----------|
| **AES-256** | **Maximum** | **Recommended** |
| AES-192 | High | Acceptable |
| AES-128 | Good | OK for most uses |

**Recommendation:** Use **AES-256** for new applications.

### Code Templates

#### Template 1: Encrypt Data with GCM (Password-Based)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# Derive key from password
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 bits
    salt=salt,
    iterations=600_000
)
key = kdf.derive(password.encode())

# Encrypt
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96 bits
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# Store: salt || nonce || ciphertext (with tag)
encrypted_data = salt + nonce + ciphertext
```

#### Template 2: Decrypt Data with GCM

```python
# Parse stored data
salt = encrypted_data[:16]
nonce = encrypted_data[16:28]
ciphertext = encrypted_data[28:]

# Derive key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600_000
)
key = kdf.derive(password.encode())

# Decrypt and verify
aesgcm = AESGCM(key)
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
# Raises exception if wrong password or tampered!
```

#### Template 3: Encrypt with Random Key (No Password)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate random 256-bit key
key = AESGCM.generate_key(bit_length=256)

# Encrypt
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# Decrypt
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

#### Template 4: Encrypt with Additional Authenticated Data (AAD)

```python
# AAD is authenticated but NOT encrypted
# Useful for headers, metadata, version info

plaintext = b"Secret message body"
aad = b"Header: version=1, sender=alice"

# Encrypt
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

# Decrypt (must provide same AAD!)
plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
```

## Security Best Practices

### ✅ DO:

1. **Use AES-256-GCM** for all new applications
2. **Generate random nonce** for each encryption: `os.urandom(12)`
3. **Use PBKDF2/Argon2** to derive keys from passwords
4. **Use high iteration count** (600,000+ for PBKDF2 in 2024)
5. **Use authenticated encryption** (GCM, or encrypt-then-MAC)
6. **Store nonce with ciphertext** (it's not secret)
7. **Use established libraries** (cryptography, libsodium)
8. **Keep libraries updated**
9. **Handle errors properly** (don't leak information)
10. **Use constant-time comparisons** for tags

### ❌ DON'T:

1. **Never use ECB mode**
2. **Never reuse nonce with same key**
3. **Never use hardcoded keys**
4. **Never use weak password derivation** (simple hash)
5. **Never implement crypto yourself**
6. **Never use unauthenticated encryption**
7. **Never use weak keys** (e.g., "password123")
8. **Never ignore authentication errors**
9. **Never use predictable IVs/nonces**
10. **Never trust user input** (validate everything)

## Common Pitfalls

### Pitfall 1: Nonce Reuse in GCM/CTR

```python
# ❌ WRONG: Reusing nonce
nonce = b"fixed_nonce!"
aesgcm = AESGCM(key)
ciphertext1 = aesgcm.encrypt(nonce, message1, None)  # OK
ciphertext2 = aesgcm.encrypt(nonce, message2, None)  # CATASTROPHIC!

# ✅ CORRECT: Generate new nonce each time
nonce1 = os.urandom(12)
nonce2 = os.urandom(12)
ciphertext1 = aesgcm.encrypt(nonce1, message1, None)  # OK
ciphertext2 = aesgcm.encrypt(nonce2, message2, None)  # OK
```

**Why it's bad:** Nonce reuse in GCM/CTR allows attackers to XOR ciphertexts and recover plaintexts!

### Pitfall 2: Weak Password Derivation

```python
# ❌ WRONG: Simple hash
import hashlib
key = hashlib.sha256(password.encode()).digest()
# Fast to brute force! Can try billions of passwords per second.

# ✅ CORRECT: Use PBKDF2 or Argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=600_000  # Slow: ~0.5 seconds per attempt
)
key = kdf.derive(password.encode())
```

### Pitfall 3: No Authentication

```python
# ❌ WRONG: CBC without authentication
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
ciphertext = cipher.encryptor().update(plaintext)
# Attacker can modify ciphertext!

# ✅ CORRECT: Use GCM (built-in authentication)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
# Any modification will be detected!
```

### Pitfall 4: Hardcoded Keys

```python
# ❌ WRONG: Hardcoded key
key = b"mysecretkey12345678901234567890"  # NEVER DO THIS!

# ✅ CORRECT: Generate random key or derive from password
key = os.urandom(32)  # Random key
# OR
key = PBKDF2(...).derive(password)  # From password
# Store securely (environment variable, key vault, HSM)
```

## Testing Your Understanding

### Exercise 1: Mode Comparison
```python
# Encrypt same message with ECB and CBC
# Observe differences in ciphertext
# Question: Which is more secure? Why?
```

### Exercise 2: Nonce Reuse
```python
# Encrypt two messages with same nonce in CTR/GCM
# XOR the ciphertexts
# Question: What information is leaked?
```

### Exercise 3: Tamper Detection
```python
# Encrypt with GCM
# Modify one byte of ciphertext
# Try to decrypt
# Question: What happens? Why?
```

### Exercise 4: Password Strength
```python
# Compare key derivation:
# - hashlib.sha256(password)
# - PBKDF2 with 1,000 iterations
# - PBKDF2 with 600,000 iterations
# Measure time for each
# Question: Which is most secure? Why?
```

## Performance Considerations

### Benchmarking AES Modes

Typical performance on modern CPU (with AES-NI):

| Mode | Speed (MB/s) | CPU Instruction |
|------|--------------|-----------------|
| ECB | 3000+ | AES-NI |
| CBC (Encrypt) | 3000+ | AES-NI |
| CBC (Decrypt) | 3000+ | AES-NI |
| CTR | 3000+ | AES-NI |
| GCM | 2000+ | AES-NI + GHASH |

**Note:** GCM is slightly slower due to authentication overhead, but it's negligible compared to security benefits.

### Optimization Tips

1. **Use AES-NI:** Ensure hardware acceleration is enabled
2. **Batch operations:** Encrypt multiple files together
3. **Stream large files:** Don't load entire file into memory
4. **Parallel processing:** GCM/CTR support parallel encryption
5. **Choose right mode:** GCM for most cases, CTR for streaming

## Real-World Applications

### Where AES is Used

- **TLS/SSL:** Secure web connections (HTTPS)
- **SSH:** Secure shell connections
- **VPN:** Virtual private networks (IPsec, WireGuard)
- **Disk encryption:** FileVault, BitLocker, LUKS
- **File encryption:** 7-Zip, VeraCrypt
- **Messaging:** Signal, WhatsApp end-to-end encryption
- **Cloud storage:** Encrypted backups
- **Databases:** Encrypted columns

### Mode Usage in Practice

- **TLS 1.3:** AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **SSH:** AES-128-CTR, AES-256-CTR, AES-128-GCM, AES-256-GCM
- **WireGuard VPN:** ChaCha20-Poly1305
- **Signal Protocol:** AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

## Next Steps

After mastering symmetric encryption:

1. **Stream Ciphers** (`../../theory/crypto3_stream_ciphers.md`)
   - ChaCha20, Salsa20
   - How they differ from block ciphers
   
2. **Public-Key Cryptography** (`../../theory/crypto4_public_key_crypto.md`)
   - RSA, Diffie-Hellman, ECC
   - Key exchange protocols
   
3. **Protocols** (`../../protocols/`)
   - How TLS uses AES-GCM
   - Hybrid encryption (RSA + AES)
   
4. **Labs** (`../../labs/`)
   - Hands-on exercises
   - Break insecure implementations
   - Build secure systems

## References

- **NIST AES:** https://csrc.nist.gov/publications/detail/fips/197/final
- **NIST GCM:** https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **OWASP Password Storage:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **Cryptography Library Docs:** https://cryptography.io/
- **Serious Cryptography** by Jean-Philippe Aumasson

---

**Remember: Use AES-256-GCM with proper nonce management for all new applications!** 🔒
