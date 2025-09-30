# Cryptography Cheatsheet

Quick reference for cryptographic algorithms, concepts, and implementations.

## 📚 Table of Contents

- [Symmetric Cryptography](#symmetric-cryptography)
- [Asymmetric Cryptography](#asymmetric-cryptography)
- [Hash Functions](#hash-functions)
- [Message Authentication Codes (MACs)](#message-authentication-codes-macs)
- [Digital Signatures](#digital-signatures)
- [Key Exchange](#key-exchange)
- [Common Vulnerabilities](#common-vulnerabilities)
- [Best Practices](#best-practices)

## 🔐 Symmetric Cryptography

### Block Ciphers

**AES (Advanced Encryption Standard)**
```bash
# Encrypt with OpenSSL (AES-256-CBC)
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.bin -k password

# Decrypt
openssl enc -d -aes-256-cbc -in encrypted.bin -out decrypted.txt -k password

# AES-256-GCM (authenticated encryption)
openssl enc -aes-256-gcm -in file.txt -out file.enc -K <hex_key> -iv <hex_iv>
```

**Key Properties:**
- Block size: 128 bits
- Key sizes: 128, 192, or 256 bits
- Modes: ECB, CBC, CTR, GCM, etc.
- **Use**: AES-256-GCM for most applications

**DES/3DES (Deprecated)**
- **Do NOT use**: Weak and obsolete
- Replaced by AES

### Stream Ciphers

**ChaCha20**
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(32)  # 256-bit key
nonce = os.urandom(16)
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"plaintext")
```

**Properties:**
- Fast and secure
- Used in TLS 1.3
- Alternative to AES in constrained environments

### Block Cipher Modes

| Mode | Authentication | Parallelizable | Use Case |
|------|---------------|----------------|----------|
| **ECB** | ❌ | ✅ | Never use (insecure) |
| **CBC** | ❌ | Decrypt only | Legacy systems |
| **CTR** | ❌ | ✅ | When combined with MAC |
| **GCM** | ✅ | ✅ | **Recommended** |
| **CCM** | ✅ | ❌ | Constrained devices |

**GCM Example (Authenticated Encryption):**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce

# Encrypt
ciphertext = aesgcm.encrypt(nonce, b"plaintext", b"additional_data")

# Decrypt
plaintext = aesgcm.decrypt(nonce, ciphertext, b"additional_data")
```

## 🔑 Asymmetric Cryptography

### RSA (Rivest-Shamir-Adleman)

**Generate RSA Keys:**
```bash
# Generate 4096-bit private key
openssl genrsa -out private.pem 4096

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with public key
openssl rsautl -encrypt -pubin -inkey public.pem -in message.txt -out encrypted.bin

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt
```

**Python Example:**
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

# Encrypt
ciphertext = public_key.encrypt(
    b"message",
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                 algorithm=hashes.SHA256(), label=None)
)

# Decrypt
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(), label=None)
)
```

**Key Sizes:**
- **2048-bit**: Minimum (valid until ~2030)
- **3072-bit**: Recommended
- **4096-bit**: Long-term security

**Common Attacks:**
- Small exponent attack (use e=65537)
- Weak random number generation
- Timing attacks
- Padding oracle attacks (use OAEP)

### Elliptic Curve Cryptography (ECC)

**Generate EC Keys:**
```bash
# List available curves
openssl ecparam -list_curves

# Generate private key (P-256)
openssl ecparam -name prime256v1 -genkey -out ec-private.pem

# Extract public key
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

**Python Example:**
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
```

**Recommended Curves:**
- **P-256** (secp256r1): Standard, widely supported
- **P-384** (secp384r1): Higher security
- **Curve25519**: Modern, fast, secure (EdDSA, ECDH)

## #️⃣ Hash Functions

### Cryptographic Hash Functions

**SHA-2 Family:**
```bash
# SHA-256
echo -n "message" | sha256sum
echo -n "message" | openssl dgst -sha256

# SHA-512
echo -n "message" | sha512sum
```

**Python:**
```python
import hashlib

# SHA-256
hash_obj = hashlib.sha256(b"message")
print(hash_obj.hexdigest())

# SHA-512
hash_obj = hashlib.sha512(b"message")
print(hash_obj.hexdigest())

# SHA-3
hash_obj = hashlib.sha3_256(b"message")
print(hash_obj.hexdigest())
```

**Hash Function Comparison:**

| Algorithm | Output Size | Security | Speed | Use |
|-----------|-------------|----------|-------|-----|
| **MD5** | 128 bits | ❌ Broken | Fast | Never use |
| **SHA-1** | 160 bits | ❌ Broken | Fast | Legacy only |
| **SHA-256** | 256 bits | ✅ Secure | Fast | **Recommended** |
| **SHA-512** | 512 bits | ✅ Secure | Fast | High security |
| **SHA-3** | Variable | ✅ Secure | Moderate | Modern alternative |
| **BLAKE2** | Variable | ✅ Secure | Very fast | Modern, fast |

**Properties:**
- **Deterministic**: Same input → same output
- **One-way**: Cannot reverse
- **Collision-resistant**: Hard to find two inputs with same hash
- **Avalanche effect**: Small change → completely different hash

## 🔏 Message Authentication Codes (MACs)

### HMAC (Hash-based MAC)

```python
import hmac
import hashlib

key = b"secret_key"
message = b"message to authenticate"

# Create HMAC
mac = hmac.new(key, message, hashlib.sha256).hexdigest()

# Verify HMAC
def verify_hmac(key, message, provided_mac):
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_mac)
```

**Bash:**
```bash
# Generate HMAC-SHA256
echo -n "message" | openssl dgst -sha256 -hmac "secret_key"
```

**Use Cases:**
- Message authentication
- API authentication
- JWT tokens
- Cookie signing

## ✍️ Digital Signatures

### RSA Signatures

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Sign message
signature = private_key.sign(
    b"message",
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Verify signature
try:
    public_key.verify(
        signature, b"message",
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Signature valid")
except:
    print("Signature invalid")
```

### ECDSA Signatures

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Sign
signature = private_key.sign(b"message", ec.ECDSA(hashes.SHA256()))

# Verify
try:
    public_key.verify(signature, b"message", ec.ECDSA(hashes.SHA256()))
    print("Valid")
except:
    print("Invalid")
```

### EdDSA (Ed25519)

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Sign
signature = private_key.sign(b"message")

# Verify
try:
    public_key.verify(signature, b"message")
    print("Valid")
except:
    print("Invalid")
```

## 🤝 Key Exchange

### Diffie-Hellman Key Exchange

**Classic DH:**
```python
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Generate parameters (do once, share publicly)
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Alice generates key pair
alice_private = parameters.generate_private_key()
alice_public = alice_private.public_key()

# Bob generates key pair
bob_private = parameters.generate_private_key()
bob_public = bob_private.public_key()

# Compute shared secret
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

# alice_shared == bob_shared
```

### ECDH (Elliptic Curve Diffie-Hellman)

```python
from cryptography.hazmat.primitives.asymmetric import ec

# Alice
alice_private = ec.generate_private_key(ec.SECP256R1())
alice_public = alice_private.public_key()

# Bob
bob_private = ec.generate_private_key(ec.SECP256R1())
bob_public = bob_private.public_key()

# Shared secret
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)
```

## ⚠️ Common Vulnerabilities

### Weak Random Number Generation
```python
# BAD: Predictable
import random
key = random.randint(0, 2**256)

# GOOD: Cryptographically secure
import os
key = os.urandom(32)  # 256-bit random key
```

### ECB Mode (Electronic Codebook)
```
# NEVER use ECB mode - identical plaintext blocks → identical ciphertext
# Use GCM, CBC, or CTR instead
```

### Padding Oracle Attack
```
# Use authenticated encryption (GCM, CCM)
# Or verify MAC before decrypting
```

### Hash Length Extension Attack
```
# Vulnerable: Hash(secret || message)
# Use HMAC instead: HMAC(secret, message)
```

### Timing Attacks
```python
# BAD: Variable-time comparison
if computed_mac == provided_mac:
    return True

# GOOD: Constant-time comparison
import hmac
if hmac.compare_digest(computed_mac, provided_mac):
    return True
```

## ✅ Best Practices

### Key Management
1. **Never hardcode keys** in source code
2. **Use key derivation functions** (PBKDF2, bcrypt, Argon2)
3. **Rotate keys** periodically
4. **Store keys securely** (HSM, key management service)
5. **Use environment variables** or secure vaults

### Algorithm Selection

**For Encryption:**
- ✅ **AES-256-GCM** (symmetric)
- ✅ **ChaCha20-Poly1305** (symmetric, mobile)
- ✅ **RSA-4096** or **ECC P-256+** (asymmetric)

**For Hashing:**
- ✅ **SHA-256** or **SHA-512**
- ✅ **BLAKE2** for high performance
- ✅ **Argon2** or **bcrypt** for passwords

**For Signatures:**
- ✅ **RSA-PSS** (2048+ bits)
- ✅ **ECDSA** (P-256+)
- ✅ **Ed25519** (modern)

**For Key Exchange:**
- ✅ **ECDH** (P-256+)
- ✅ **X25519** (modern)

### Password Storage
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Generate salt
salt = os.urandom(16)

# Derive key from password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = kdf.derive(b"password")

# For password verification, use bcrypt or Argon2
import bcrypt
hashed = bcrypt.hashpw(b"password", bcrypt.gensalt())
if bcrypt.checkpw(b"password", hashed):
    print("Password matches")
```

### Authenticated Encryption
```
Always use authenticated encryption:
- AES-GCM (most common)
- ChaCha20-Poly1305 (mobile/embedded)
- Or: Encrypt-then-MAC with separate keys
```

### IV/Nonce Generation
```python
# Generate random IV for each encryption
import os
iv = os.urandom(16)  # 128-bit IV for AES-CBC
nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

# NEVER reuse IV/nonce with same key
```

## 🔬 Testing & Validation

### Test Vectors
```python
# Always test crypto implementations against known test vectors
# Example: AES-256 test vector
key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
expected_ciphertext = bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")
```

### Common Test Cases
1. Empty input
2. Single byte input
3. Block-aligned input
4. Non-aligned input
5. Maximum size input
6. Invalid keys/parameters
7. Known test vectors

## 📚 References

- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**Remember**: Don't roll your own crypto! Use well-tested, established libraries.
