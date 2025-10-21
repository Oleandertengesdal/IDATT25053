# Cryptography Fundamentals

## 📚 Overview

Cryptography is the foundation of modern information security, providing confidentiality, integrity, authentication, and non-repudiation. This document covers the essential cryptographic concepts, algorithms, and best practices needed for secure software development.

---

## 🎯 Cryptographic Goals

### The CIA Triad

**1. Confidentiality**
- Only authorized parties can read the data
- Achieved through: Encryption

**2. Integrity**
- Data cannot be modified without detection
- Achieved through: Hashing, MACs, digital signatures

**3. Availability**
- Data and systems are accessible when needed
- Achieved through: Redundancy, backups, DoS prevention

### Additional Security Properties

**4. Authentication**
- Verify the identity of parties
- Achieved through: Passwords, certificates, digital signatures

**5. Non-repudiation**
- Parties cannot deny their actions
- Achieved through: Digital signatures, audit logs

---

## 🔐 Symmetric Cryptography

### Overview

**Symmetric encryption** uses the same key for both encryption and decryption.

**Characteristics**:
- ✅ Fast (hardware acceleration available)
- ✅ Suitable for large amounts of data
- ❌ Key distribution problem (how to share the key securely?)

### Common Algorithms

#### AES (Advanced Encryption Standard)

**Key Sizes**: 128, 192, or 256 bits  
**Block Size**: 128 bits  
**Status**: Current standard, secure

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate key and IV
key = os.urandom(32)  # 256 bits for AES-256
iv = os.urandom(16)   # 128 bits (AES block size)

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decrypt
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
```

#### ChaCha20

**Key Size**: 256 bits  
**Nonce**: 96 bits  
**Status**: Modern alternative to AES, used in TLS 1.3

**Advantages**:
- Faster than AES on systems without hardware acceleration
- Constant-time implementation (resistant to timing attacks)
- Used in WireGuard VPN

### Modes of Operation

Block ciphers like AES operate on fixed-size blocks. Modes of operation define how to encrypt data larger than one block.

#### ❌ ECB (Electronic Codebook) - NEVER USE

**How it works**: Each block encrypted independently

**Problem**: Identical plaintext blocks → identical ciphertext blocks (reveals patterns)

```
Plaintext:  [Block 1] [Block 2] [Block 1] [Block 3]
Ciphertext: [Cipher 1] [Cipher 2] [Cipher 1] [Cipher 3]
                                   ↑ Same! Pattern revealed!
```

**Famous example**: ECB-encrypted image still shows the original image outline

#### ✅ CBC (Cipher Block Chaining)

**How it works**: Each block XORed with previous ciphertext before encryption

**Requires**: Random IV (Initialization Vector)

**Properties**:
- ✅ Hides patterns
- ❌ No authentication (use HMAC separately)
- ❌ Padding oracle attacks possible
- ❌ Not parallelizable

```python
from cryptography.hazmat.primitives.ciphers import modes

# CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
```

#### ✅ GCM (Galois/Counter Mode) - RECOMMENDED

**How it works**: Counter mode encryption + authentication

**Properties**:
- ✅ **Authenticated encryption** (both confidentiality and integrity)
- ✅ Parallelizable (fast)
- ✅ Hardware accelerated
- ✅ No padding needed

**Output**: Ciphertext + authentication tag

```python
from cryptography.hazmat.primitives.ciphers import modes

# GCM mode (authenticated encryption)
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
encryptor = cipher.encryptor()

# Encrypt
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Get authentication tag
tag = encryptor.tag

# Decrypt (will fail if tampered)
decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
```

#### Other Modes

- **CTR (Counter)**: Parallelizable, no padding, but no authentication
- **CFB/OFB**: Stream cipher modes
- **XTS**: For disk encryption (not for general use)

### Key Management

**Key Generation**:
```python
import secrets

# ✅ Cryptographically secure random key
key = secrets.token_bytes(32)  # 256 bits

# ❌ NOT secure
import random
key = random.randbytes(32)  # Predictable!
```

**Key Derivation from Password**:
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Derive key from password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000
)
key = kdf.derive(password.encode())
```

---

## 🔑 Asymmetric Cryptography

### Overview

**Asymmetric encryption** uses different keys for encryption and decryption.

**Key Pair**:
- **Public Key**: Can be shared freely, used for encryption and signature verification
- **Private Key**: Must be kept secret, used for decryption and signing

**Use Cases**:
- Secure key exchange
- Digital signatures
- SSL/TLS certificates

### RSA (Rivest-Shamir-Adleman)

**Key Sizes**: Minimum 2048 bits, recommended 4096 bits  
**Status**: Widely used, but slower than ECC

**Operations**:
1. **Encryption**: Encrypt with public key, decrypt with private key
2. **Signatures**: Sign with private key, verify with public key

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Encrypt with public key
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt with private key
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

**Important**: RSA can only encrypt small amounts of data (less than key size). For larger data:
1. Generate random AES key
2. Encrypt data with AES
3. Encrypt AES key with RSA public key
4. Send both encrypted data and encrypted key

### ECC (Elliptic Curve Cryptography)

**Key Sizes**: 256 bits (equivalent to 3072-bit RSA)  
**Status**: Modern, preferred for new systems

**Advantages**:
- Much smaller keys than RSA for equivalent security
- Faster operations
- Lower memory usage

**Common Curves**:
- **secp256r1 (P-256)**: NIST standard, widely supported
- **secp384r1 (P-384)**: Higher security
- **Curve25519**: Modern, fast, constant-time

```python
from cryptography.hazmat.primitives.asymmetric import ec

# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
```

### Digital Signatures

**Purpose**: Prove that a message came from a specific sender and hasn't been modified

**Process**:
1. Hash the message
2. Sign the hash with private key
3. Recipient verifies signature with public key

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Sign message
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature valid!")
except:
    print("Signature invalid!")
```

---

## #️⃣ Cryptographic Hash Functions

### Overview

**Hash function**: Takes arbitrary input, produces fixed-size output (digest)

**Properties**:
1. **Deterministic**: Same input always produces same output
2. **Fast**: Quick to compute
3. **One-way**: Cannot reverse (find input from output)
4. **Avalanche effect**: Small input change → completely different output
5. **Collision-resistant**: Extremely hard to find two inputs with same output

### Common Hash Functions

#### SHA-256 (Secure Hash Algorithm)

**Output Size**: 256 bits (32 bytes)  
**Status**: Current standard, secure

```python
import hashlib

hash = hashlib.sha256(b"Hello, World!").hexdigest()
# Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```

#### SHA-3

**Output Size**: Variable (SHA3-256, SHA3-512, etc.)  
**Status**: Newest NIST standard, different design from SHA-2

```python
hash = hashlib.sha3_256(b"Hello, World!").hexdigest()
```

#### ❌ MD5 and SHA-1 - BROKEN, DON'T USE

**MD5**: Completely broken, collisions can be generated in seconds  
**SHA-1**: Broken, Google demonstrated collision in 2017

**Only acceptable use**: Non-security applications (checksums for file integrity where attacker is not a concern)

### Password Hashing

**Regular hash functions are TOO FAST for passwords** → enables brute force

**Solution**: Use password hashing functions designed to be slow

#### PBKDF2 (Password-Based Key Derivation Function 2)

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

salt = os.urandom(32)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000  # High iteration count = slow
)
hash = kdf.derive(password.encode())
```

**Iterations**: OWASP recommends 100,000+ for PBKDF2-SHA256

#### bcrypt

**Popular**: Used by many frameworks  
**Advantage**: Designed to be slow, adaptive (can increase cost)

```python
import bcrypt

# Hash password
salt = bcrypt.gensalt(rounds=12)  # Cost factor
hash = bcrypt.hashpw(password.encode(), salt)

# Verify password
if bcrypt.checkpw(password.encode(), hash):
    print("Correct password")
```

#### Argon2 (Winner of Password Hashing Competition)

**Status**: Current best practice (2015)  
**Advantages**: Resistant to GPU/ASIC attacks, memory-hard

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# Hash password
hash = ph.hash(password)

# Verify password
try:
    ph.verify(hash, password)
    print("Correct password")
except:
    print("Wrong password")
```

### Message Authentication Codes (MAC)

**Purpose**: Verify message integrity AND authenticity (sender verification)

#### HMAC (Hash-based MAC)

```python
import hmac
import hashlib

# Create HMAC
secret_key = b"shared secret key"
message = b"Important message"
tag = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

# Verify HMAC
received_tag = "..."
expected_tag = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

if hmac.compare_digest(received_tag, expected_tag):  # Timing-safe comparison
    print("Message authentic")
```

**Use case**: API authentication, cookie integrity

---

## 🔒 Practical Cryptography

### Authenticated Encryption

**Problem**: Encryption alone doesn't prevent tampering

**Solution**: Combine encryption and authentication

**Options**:
1. **Use authenticated encryption mode (AES-GCM)** ← Recommended
2. **Encrypt-then-MAC**: Encrypt first, then HMAC the ciphertext
3. ❌ **MAC-then-encrypt**: DON'T (vulnerable)

```python
# ✅ OPTION 1: AES-GCM (easiest)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag  # Authentication tag

# ✅ OPTION 2: Encrypt-then-MAC
from cryptography.hazmat.primitives import hmac, hashes

# Encrypt
cipher = Cipher(algorithms.AES(key_encrypt), modes.CBC(iv))
ciphertext = cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()

# Then MAC
h = hmac.HMAC(key_mac, hashes.SHA256())
h.update(ciphertext)
tag = h.finalize()
```

### Hybrid Encryption

**Problem**: RSA is slow and can only encrypt small amounts

**Solution**: Use RSA to encrypt a symmetric key, use symmetric encryption for data

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate symmetric key
symmetric_key = Fernet.generate_key()
f = Fernet(symmetric_key)

# Encrypt data with symmetric key (fast)
ciphertext_data = f.encrypt(large_data)

# Encrypt symmetric key with RSA public key
ciphertext_key = public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Send both: ciphertext_data + ciphertext_key

# Recipient: decrypt symmetric key with RSA private key, then decrypt data
```

### Random Number Generation

**Critical**: Weak random numbers break cryptography

```python
import secrets  # ✅ Cryptographically secure

# Generate random bytes
random_bytes = secrets.token_bytes(32)

# Generate random string (URL-safe)
random_string = secrets.token_urlsafe(32)

# Generate random hex string
random_hex = secrets.token_hex(32)

# DON'T USE:
import random  # ❌ NOT cryptographically secure
random.randbytes(32)  # Predictable!
```

### Key Derivation

**Problem**: Need multiple keys from one password

**Solution**: Key Derivation Function (KDF)

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Derive multiple keys from master key
master_key = b"..."
info = b"encryption key"

kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=info
)
derived_key = kdf.derive(master_key)
```

---

## ⚠️ Common Cryptographic Mistakes

### 1. Using Weak Algorithms

❌ **DON'T**:
- MD5, SHA-1 (broken)
- DES, 3DES (weak)
- RC4 (broken)
- Custom encryption algorithms

✅ **DO**:
- SHA-256, SHA-3
- AES-256
- RSA-2048+, ECC
- Established libraries

### 2. Hardcoding Keys

```python
# ❌ NEVER
SECRET_KEY = "my_secret_key_12345"

# ✅ USE
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
```

### 3. Reusing IVs/Nonces

```python
# ❌ WRONG: Same IV for multiple messages
iv = b"0" * 16
for message in messages:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # ... encrypt

# ✅ CORRECT: Random IV per message
for message in messages:
    iv = os.urandom(16)  # New IV each time
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
```

### 4. Using ECB Mode

❌ **NEVER USE ECB** - it reveals patterns in data

### 5. Not Authenticating Encrypted Data

❌ **Encryption alone** doesn't prevent tampering

✅ **Use authenticated encryption** (AES-GCM) or Encrypt-then-MAC

### 6. Weak Password Hashing

```python
# ❌ TOO FAST
hash = hashlib.sha256(password.encode()).hexdigest()

# ✅ SLOW (resistant to brute force)
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
```

### 7. Predictable Random Numbers

```python
# ❌ NOT CRYPTOGRAPHICALLY SECURE
import random
token = random.randint(0, 1000000)

# ✅ CRYPTOGRAPHICALLY SECURE
import secrets
token = secrets.token_urlsafe(32)
```

---

## 📋 Cryptography Best Practices

### General Principles

✅ **Use established libraries** (cryptography, NaCl/libsodium)  
✅ **Never implement crypto algorithms yourself**  
✅ **Keep crypto libraries updated**  
✅ **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)  
✅ **Generate keys securely** (secrets module)  
✅ **Use unique IVs/nonces** for each encryption  
✅ **Use strong KDFs** for password hashing (Argon2, bcrypt, PBKDF2)  
✅ **Protect keys** (environment variables, key vaults, HSMs)  
✅ **Plan for key rotation**  

### Algorithm Selection

| Purpose | Recommended Algorithm | Key/Output Size |
|---------|----------------------|-----------------|
| Symmetric Encryption | AES-256-GCM | 256-bit key |
| Asymmetric Encryption | RSA-2048+ or ECC P-256 | 2048+ bits / 256 bits |
| Hashing | SHA-256, SHA-3 | 256 bits |
| Password Hashing | Argon2, bcrypt, PBKDF2 | 256 bits |
| Message Authentication | HMAC-SHA256 | 256-bit key |
| Random Numbers | secrets module | N/A |
| Key Derivation | PBKDF2, HKDF | 256 bits |

---

## 📚 Additional Resources

- [Cryptography Library Documentation](https://cryptography.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines)
- *Cryptography Engineering* by Ferguson, Schneier, and Kohno

---

**Last Updated**: October 14, 2025  
**Version**: 1.0
