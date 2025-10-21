# Cryptographic Attacks and Vulnerabilities Guide
**IDATT2503 - Security in Software Systems**

## Table of Contents
1. [Common Cryptographic Attacks](#common-attacks)
2. [Implementation Vulnerabilities](#implementation-vulnerabilities)
3. [Protocol Attacks](#protocol-attacks)
4. [Side-Channel Attacks](#side-channel-attacks)
5. [Defense Strategies](#defense-strategies)

---

## Common Cryptographic Attacks

### 1. Brute Force Attacks

**Description**: Trying all possible keys until the correct one is found.

**Target**: All encryption algorithms

**Example Complexity**:
- DES (56-bit): ~2^56 = 72 quadrillion possibilities
- AES-128: ~2^128 possibilities (practically impossible)
- AES-256: ~2^256 possibilities (universe-ending impossible)

**Defense**:
- Use sufficiently long keys (AES-256, RSA-2048+)
- Key derivation functions with high iteration counts
- Rate limiting for password attempts

```python
# Weak: Short key
weak_key = "abc"  # Only 3 characters = small keyspace

# Strong: Proper key length
import os
strong_key = os.urandom(32)  # 256 bits = 2^256 possibilities
```

---

### 2. Dictionary Attacks

**Description**: Using a list of common passwords/phrases to crack hashes.

**Target**: Password hashes, weak passphrases

**Example**:
```python
# Common passwords (NEVER use these!)
weak_passwords = [
    "password", "123456", "qwerty", "letmein",
    "admin", "welcome", "monkey", "dragon"
]

# Attacker tries hashing each one
import hashlib
for password in weak_passwords:
    hash_attempt = hashlib.sha256(password.encode()).hexdigest()
    # Compare with stolen hash
```

**Defense**:
- Enforce strong password policies
- Use password strength meters
- Implement multi-factor authentication
- Use proper password hashing (bcrypt, Argon2, PBKDF2)

---

### 3. Rainbow Table Attacks

**Description**: Pre-computed tables of password hashes for quick lookup.

**Target**: Unsalted password hashes

**How it works**:
1. Attacker pre-computes hashes for millions of passwords
2. Steals password database
3. Looks up stolen hashes in rainbow table

**Vulnerable Code**:
```python
# VULNERABLE: No salt!
def bad_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# All users with password "password123" have same hash:
# 482c811da5d5b4bc6d497ffa98491e38
```

**Defense**:
```python
# SECURE: Use unique salt per password
import os
import hashlib

def secure_password_hash(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
    return salt + key  # Store salt with hash

# Now each password has unique hash, even if passwords are identical!
```

---

### 4. Birthday Attack

**Description**: Exploiting birthday paradox to find hash collisions.

**Math**: With n-bit hash, collision probability becomes high after ~2^(n/2) attempts.

**Example**:
- MD5 (128-bit): Collisions after ~2^64 attempts (achievable!)
- SHA-256 (256-bit): Collisions after ~2^128 attempts (still infeasible)

**Impact**: Can forge digital signatures if hash is weak.

**Defense**:
- Use SHA-256 or SHA-3 (not MD5 or SHA-1)
- Use longer hash outputs for critical applications

---

### 5. Chosen Plaintext Attack (CPA)

**Description**: Attacker can encrypt chosen plaintexts and analyze ciphertexts.

**Example Scenario**:
- Attacker can submit messages to encryption oracle
- Analyzes patterns in outputs
- Can break ECB mode easily

**ECB Mode Vulnerability**:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# VULNERABLE: ECB mode
key = b'sixteen byte key'
cipher = AES.new(key, AES.MODE_ECB)

# Same plaintext blocks produce same ciphertext blocks!
plaintext = b'AAAA' * 100
ciphertext = cipher.encrypt(pad(plaintext, 16))

# Attacker can detect patterns and repeated blocks
```

**Defense**:
- Use randomized IV/nonce (CBC, CTR, GCM)
- Use authenticated encryption (GCM)
- Never use ECB mode

---

### 6. Chosen Ciphertext Attack (CCA)

**Description**: Attacker can decrypt chosen ciphertexts (excluding target).

**Target**: Unauthenticated encryption modes

**Attack Example**:
```python
# Attacker modifies ciphertext
# If no authentication, may decrypt to valid plaintext
# Can reveal information about original message
```

**Defense**:
- Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Verify MAC/tag before decryption
- Never decrypt unauthenticated data

---

### 7. Replay Attack

**Description**: Attacker captures and resends valid encrypted messages.

**Example Scenario**:
1. Alice sends encrypted "Transfer $100 to Bob"
2. Attacker captures encrypted message
3. Attacker resends same message multiple times
4. Multiple transfers occur!

**Defense**:
```python
import time
import hmac
import hashlib

def create_message(data, secret_key):
    timestamp = str(time.time())
    nonce = os.urandom(16).hex()
    message = f"{data}|{timestamp}|{nonce}"
    
    # Sign message
    signature = hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()
    return f"{message}|{signature}"

def verify_message(message, secret_key, max_age=60):
    parts = message.split('|')
    data, timestamp, nonce, signature = parts
    
    # Verify signature
    expected = f"{data}|{timestamp}|{nonce}"
    expected_sig = hmac.new(secret_key, expected.encode(), hashlib.sha256).hexdigest()
    
    if signature != expected_sig:
        return False, "Invalid signature"
    
    # Check timestamp (prevent replay)
    if time.time() - float(timestamp) > max_age:
        return False, "Message expired"
    
    # Store nonce to prevent reuse
    # (In production, use database/cache)
    
    return True, data
```

---

### 8. Man-in-the-Middle (MITM) Attack

**Description**: Attacker intercepts and potentially modifies communication.

**Vulnerable Scenario**:
```python
# Unprotected Diffie-Hellman
# Alice generates: a, sends g^a
# Bob generates: b, sends g^b
# Eve intercepts both, sends her own values
# Eve can now decrypt and re-encrypt all traffic!
```

**Defense**:
```python
# Authenticated Diffie-Hellman
# 1. Perform DH exchange
# 2. Sign exchanged values with private keys
# 3. Verify signatures with trusted public keys
# 4. Optionally use certificates (PKI)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

def authenticated_dh(my_private_key, my_signing_key, peer_public_key, peer_verify_key):
    # Perform ECDH
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Sign my public key
    my_public_key = my_private_key.public_key()
    signature = my_signing_key.sign(
        my_public_key.public_bytes(...),
        ec.ECDSA(hashes.SHA256())
    )
    
    # Verify peer's signature
    peer_verify_key.verify(
        peer_signature,
        peer_public_key.public_bytes(...),
        ec.ECDSA(hashes.SHA256())
    )
    
    return shared_secret
```

---

## Implementation Vulnerabilities

### 1. Hardcoded Keys

**Problem**: Encryption keys embedded in source code.

**Vulnerable**:
```python
# NEVER DO THIS!
SECRET_KEY = "MySecretKey123"
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
```

**Secure**:
```python
import os
from dotenv import load_dotenv

# Load from environment variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
API_KEY = os.getenv('API_KEY')

# Or use key management services
# - AWS KMS, Azure Key Vault, HashiCorp Vault
# - Hardware Security Modules (HSM)
```

---

### 2. Weak Random Number Generation

**Problem**: Using predictable random number generators.

**Vulnerable**:
```python
import random

# INSECURE for crypto!
key = random.randint(0, 2**256)  # Predictable seed
iv = bytes([random.randint(0, 255) for _ in range(16)])
```

**Secure**:
```python
import os
import secrets

# Cryptographically secure random
key = os.urandom(32)  # Uses /dev/urandom on Unix
nonce = secrets.token_bytes(16)
token = secrets.token_hex(32)
```

---

### 3. Improper IV/Nonce Reuse

**Problem**: Reusing IV with same key breaks security.

**Vulnerable**:
```python
# VULNERABLE: Reusing IV
key = get_random_bytes(32)
iv = get_random_bytes(16)  # Generated once

# Later...
cipher1 = AES.new(key, AES.MODE_CBC, iv)  # Uses same IV
cipher2 = AES.new(key, AES.MODE_CBC, iv)  # BROKEN!

# With CTR mode, reuse is catastrophic:
# C1 ⊕ C2 = P1 ⊕ P2 (reveals plaintext!)
```

**Secure**:
```python
# Generate new IV for each encryption
def encrypt_message(plaintext, key):
    iv = get_random_bytes(16)  # New IV every time!
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    return iv + ciphertext  # Store IV with ciphertext
```

---

### 4. Padding Oracle Attack

**Problem**: Error messages reveal padding validity.

**Vulnerable**:
```python
def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    try:
        return unpad(plaintext, 16)
    except ValueError:
        raise Exception("Invalid padding!")  # Leaks information!
```

**Attack**: Attacker modifies ciphertext and observes errors to decrypt byte-by-byte.

**Defense**:
- Use authenticated encryption (GCM)
- Return same error for all decryption failures
- Constant-time operations

---

## Side-Channel Attacks

### 1. Timing Attack

**Description**: Measuring operation time reveals information.

**Vulnerable**:
```python
def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Returns immediately!
    return True

# Time taken reveals how many characters matched!
```

**Secure**:
```python
import hmac

def secure_compare(a, b):
    return hmac.compare_digest(a, b)  # Constant-time

# Or manual implementation:
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
```

---

### 2. Power Analysis

**Description**: Measuring power consumption during crypto operations.

**Types**:
- Simple Power Analysis (SPA)
- Differential Power Analysis (DPA)

**Defense**:
- Use constant-time implementations
- Add noise to power consumption
- Use hardware countermeasures

---

### 3. Cache-Timing Attack

**Description**: Analyzing CPU cache behavior.

**Example**: Recovering AES keys by observing cache hits/misses during table lookups.

**Defense**:
- Use AES-NI (hardware acceleration)
- Bitsliced implementations
- Constant-time algorithms

---

## Protocol Attacks

### 1. SSL/TLS Vulnerabilities

**Historic Attacks**:
- **POODLE**: Padding oracle in SSL 3.0
- **BEAST**: CBC vulnerability in TLS 1.0
- **Heartbleed**: Buffer over-read in OpenSSL
- **CRIME/BREACH**: Compression attacks

**Defense**:
- Use TLS 1.3 (removes vulnerable features)
- Disable older TLS versions
- Keep libraries updated
- Use HSTS (HTTP Strict Transport Security)

---

### 2. Downgrade Attacks

**Description**: Force use of weaker crypto algorithms.

**Example**:
1. Client supports TLS 1.3 and TLS 1.0
2. Attacker intercepts, modifies to only offer TLS 1.0
3. Connection uses weak crypto

**Defense**:
- Disable legacy protocols
- Use TLS_FALLBACK_SCSV
- Certificate pinning

---

## Defense Strategies

### Defense in Depth

```python
class SecureCommunication:
    """Example of layered security"""
    
    def __init__(self):
        # 1. Use strong algorithms
        self.cipher_suite = "AES-256-GCM"
        
        # 2. Proper key management
        self.key = self.load_key_from_secure_storage()
        
        # 3. Add authentication
        self.hmac_key = self.derive_key(self.key, "HMAC")
        
        # 4. Use TLS for transport
        self.use_tls_1_3 = True
        
        # 5. Add application-level encryption
        self.encrypt_sensitive_fields = True
        
        # 6. Implement rate limiting
        self.max_requests_per_minute = 60
        
        # 7. Add monitoring
        self.log_crypto_failures = True
```

### Security Checklist

✅ **Algorithm Selection**:
- [ ] AES-256-GCM for symmetric encryption
- [ ] RSA-2048+ or ECC-256+ for asymmetric
- [ ] SHA-256+ for hashing
- [ ] Argon2/bcrypt/PBKDF2 for passwords
- [ ] TLS 1.3 for transport

✅ **Implementation**:
- [ ] Use cryptographically secure RNG
- [ ] Generate new IV/nonce for each encryption
- [ ] Use authenticated encryption
- [ ] Constant-time comparisons for secrets
- [ ] No hardcoded keys
- [ ] Proper error handling (no information leakage)

✅ **Key Management**:
- [ ] Store keys securely (HSM, key vault, env variables)
- [ ] Rotate keys regularly
- [ ] Use key derivation functions
- [ ] Separate keys for different purposes
- [ ] Secure key deletion when no longer needed

✅ **Testing**:
- [ ] Test against known attack vectors
- [ ] Penetration testing
- [ ] Code review by security experts
- [ ] Use static analysis tools
- [ ] Monitor for vulnerabilities in dependencies

---

## Real-World Examples

### Example 1: Secure File Storage

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename: str, password: str):
    """Securely encrypt a file"""
    # Generate unique salt
    salt = os.urandom(16)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Encrypt file
    fernet = Fernet(key)
    with open(filename, 'rb') as f:
        data = f.read()
    
    encrypted = fernet.encrypt(data)
    
    # Store salt + encrypted data
    with open(filename + '.enc', 'wb') as f:
        f.write(salt + encrypted)
    
    print(f"✓ Encrypted {filename}")

def decrypt_file(filename: str, password: str):
    """Securely decrypt a file"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Extract salt and encrypted data
    salt = data[:16]
    encrypted = data[16:]
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Decrypt
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    
    # Save decrypted file
    output = filename.replace('.enc', '.dec')
    with open(output, 'wb') as f:
        f.write(decrypted)
    
    print(f"✓ Decrypted to {output}")
```

---

## Resources for Further Learning

### Tools for Testing
- **Cryptopals**: https://cryptopals.com/
- **CryptoHack**: https://cryptohack.org/
- **PicoCTF**: https://picoctf.org/

### Vulnerability Databases
- **CVE**: https://cve.mitre.org/
- **NVD**: https://nvd.nist.gov/
- **CWE**: https://cwe.mitre.org/

### Standards and Guidelines
- **NIST**: https://csrc.nist.gov/
- **OWASP**: https://owasp.org/
- **RFC 8446**: TLS 1.3 specification

---

## Summary

**Key Takeaways**:

1. **Never roll your own crypto** - Use established libraries
2. **Defense in depth** - Multiple layers of security
3. **Stay updated** - New vulnerabilities discovered constantly
4. **Test thoroughly** - Security testing is critical
5. **Follow best practices** - They exist for good reasons
6. **Assume breach** - Design for compromise scenarios
7. **Keep it simple** - Complexity is the enemy of security

**Remember**: The goal is not to make systems unbreakable, but to make attacks economically infeasible.
