# Cryptography Guide for IDATT2503
**NTNU Trondheim - Security in Software Systems**

## Table of Contents
1. [Introduction to Cryptography](#introduction)
2. [Symmetric Encryption](#symmetric-encryption)
3. [Asymmetric Encryption](#asymmetric-encryption)
4. [Hash Functions](#hash-functions)
5. [Digital Signatures](#digital-signatures)
6. [Key Exchange](#key-exchange)
7. [Common Protocols](#common-protocols)
8. [Best Practices](#best-practices)

---

## Introduction to Cryptography

Cryptography is the practice and study of techniques for secure communication in the presence of adversaries. It encompasses:

- **Confidentiality**: Ensuring data is only readable by authorized parties
- **Integrity**: Ensuring data hasn't been tampered with
- **Authentication**: Verifying the identity of parties
- **Non-repudiation**: Preventing denial of actions

### Security Principles

**Kerckhoffs's Principle**: A cryptosystem should be secure even if everything about the system, except the key, is public knowledge.

**Key Management**: The security of a cryptographic system depends on the secrecy of the key, not the algorithm.

---

## Symmetric Encryption

Symmetric encryption uses the same key for both encryption and decryption.

### Characteristics
- **Fast**: Suitable for encrypting large amounts of data
- **Key Distribution Problem**: Both parties need the same secret key
- **Key Size**: Typically 128, 192, or 256 bits

### Common Algorithms

#### AES (Advanced Encryption Standard)
- **Block cipher**: Encrypts data in fixed-size blocks (128 bits)
- **Key sizes**: 128, 192, or 256 bits
- **Industry standard**: Most widely used symmetric encryption
- **Security**: Currently considered secure

```python
# AES Example (see examples/cryptography/)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # 256-bit key
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(b"Secret message")
```

#### DES/3DES (Deprecated)
- **DES**: 56-bit key (broken, do not use)
- **3DES**: Applies DES three times (deprecated, use AES)

### Block Cipher Modes of Operation

1. **ECB (Electronic Codebook)** - ⚠️ Insecure
   - Each block encrypted independently
   - Same plaintext = same ciphertext (reveals patterns)
   - **Never use for real applications**

2. **CBC (Cipher Block Chaining)**
   - Each block XORed with previous ciphertext block
   - Requires Initialization Vector (IV)
   - IV must be unpredictable

3. **CTR (Counter)**
   - Converts block cipher into stream cipher
   - Parallelizable
   - Requires unique nonce for each message

4. **GCM (Galois/Counter Mode)** - ⭐ Recommended
   - Provides both encryption and authentication
   - Fast and secure
   - Standard for TLS 1.3

### Stream Ciphers

- **ChaCha20**: Modern stream cipher, faster than AES on devices without hardware acceleration
- **Salsa20**: Predecessor to ChaCha20

---

## Asymmetric Encryption

Uses a pair of keys: public key (encryption) and private key (decryption).

### Characteristics
- **Slow**: 100-1000x slower than symmetric encryption
- **Key Distribution**: Public key can be shared openly
- **Use Cases**: Key exchange, digital signatures, hybrid encryption

### RSA (Rivest-Shamir-Adleman)

**Key Generation**:
1. Choose two large prime numbers p and q
2. Compute n = p × q (modulus)
3. Compute φ(n) = (p-1)(q-1)
4. Choose e (public exponent, typically 65537)
5. Compute d (private exponent): d ≡ e⁻¹ (mod φ(n))

**Public Key**: (n, e)  
**Private Key**: (n, d)

**Encryption**: C = M^e mod n  
**Decryption**: M = C^d mod n

```python
# RSA Example
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate keys
key = RSA.generate(2048)
public_key = key.publickey()

# Encrypt
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(b"Secret message")

# Decrypt
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)
```

**Key Sizes**:
- 2048 bits: Minimum for modern use
- 3072 bits: Recommended for long-term security
- 4096 bits: High security (slower)

**Padding**: Always use OAEP (Optimal Asymmetric Encryption Padding) to prevent attacks

### Elliptic Curve Cryptography (ECC)

More efficient than RSA with smaller key sizes:

- **256-bit ECC** ≈ **3072-bit RSA** in security
- Faster operations
- Smaller keys and signatures

**Common Curves**:
- P-256 (secp256r1/prime256v1): NIST standard
- P-384, P-521: Higher security levels
- Curve25519: Modern, fast, secure
- Ed25519: For digital signatures

---

## Hash Functions

One-way functions that map data of arbitrary size to fixed-size output.

### Properties

1. **Deterministic**: Same input always produces same output
2. **Fast to compute**
3. **Pre-image resistance**: Hard to find input from hash
4. **Second pre-image resistance**: Hard to find different input with same hash
5. **Collision resistance**: Hard to find two inputs with same hash
6. **Avalanche effect**: Small input change causes large output change

### Common Hash Functions

#### SHA-2 Family (Secure Hash Algorithm)
- **SHA-256**: 256-bit output, widely used
- **SHA-384**: 384-bit output
- **SHA-512**: 512-bit output

```python
import hashlib

# SHA-256
hash_object = hashlib.sha256(b"Hello, World!")
hex_dig = hash_object.hexdigest()
print(f"SHA-256: {hex_dig}")
```

#### SHA-3 (Keccak)
- Newest SHA standard
- Different internal structure from SHA-2
- SHA3-256, SHA3-384, SHA3-512

#### Deprecated Hash Functions ⚠️
- **MD5**: Broken, collision attacks exist (32-bit hash)
- **SHA-1**: Deprecated, collision attacks demonstrated (40-bit hash)

### Hash-based Message Authentication Code (HMAC)

Provides both integrity and authenticity using a secret key:

```python
import hmac
import hashlib

key = b"secret_key"
message = b"Important message"
signature = hmac.new(key, message, hashlib.sha256).hexdigest()
```

**Use Cases**:
- API authentication
- Message integrity verification
- Token generation

---

## Digital Signatures

Provide authentication, integrity, and non-repudiation.

### How Digital Signatures Work

1. **Signing**: Hash the message, then encrypt hash with private key
2. **Verification**: Decrypt signature with public key, compare with message hash

```
Sign:    Signature = Encrypt(Hash(Message), PrivateKey)
Verify:  Hash(Message) == Decrypt(Signature, PublicKey)
```

### RSA Signatures

```python
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Sign
h = SHA256.new(message)
signature = pkcs1_15.new(private_key).sign(h)

# Verify
try:
    pkcs1_15.new(public_key).verify(h, signature)
    print("Signature is valid")
except (ValueError, TypeError):
    print("Signature is invalid")
```

### ECDSA (Elliptic Curve Digital Signature Algorithm)

Smaller signatures than RSA with equivalent security.

### EdDSA (Edwards-curve Digital Signature Algorithm)

Modern alternative using Ed25519:
- Fast signing and verification
- Deterministic (no random number needed)
- Immune to many side-channel attacks

---

## Key Exchange

Securely establish shared secrets over insecure channels.

### Diffie-Hellman Key Exchange

**Classic DH**:
1. Alice and Bob agree on public parameters (p, g)
2. Alice chooses secret a, sends A = g^a mod p
3. Bob chooses secret b, sends B = g^b mod p
4. Both compute shared secret: s = B^a mod p = A^b mod p

**Security**: Based on discrete logarithm problem

### Elliptic Curve Diffie-Hellman (ECDH)

Same concept but using elliptic curve operations:
- More efficient
- Smaller key sizes
- Commonly used in TLS 1.3

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate keys
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Exchange and derive shared secret
shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)
```

### Man-in-the-Middle Protection

Basic DH is vulnerable to MITM attacks. Solutions:
- **Authenticated DH**: Combine with digital signatures
- **DHE**: Ephemeral DH with authentication
- **ECDHE**: Elliptic Curve DHE (used in TLS)

---

## Common Protocols

### TLS (Transport Layer Security)

**TLS Handshake (Simplified)**:
1. Client Hello: Supported cipher suites
2. Server Hello: Selected cipher suite, certificate
3. Key Exchange: ECDHE for forward secrecy
4. Finished: Begin encrypted communication

**TLS 1.3 Improvements**:
- Removed weak ciphers and algorithms
- Faster handshake (1-RTT)
- Forward secrecy by default
- Encrypted handshake data

### SSH (Secure Shell)

- Uses hybrid encryption
- Key exchange: ECDH or DH
- Symmetric encryption: AES-GCM, ChaCha20-Poly1305
- Authentication: Public key or password

### PGP/GPG (Pretty Good Privacy)

- Email encryption and signing
- Web of trust model
- Uses hybrid encryption (RSA + AES)

---

## Best Practices

### Key Management

1. **Generate Keys Securely**: Use cryptographically secure random number generators
2. **Key Rotation**: Regularly rotate keys
3. **Key Storage**: 
   - Never hardcode keys in source code
   - Use hardware security modules (HSM) for critical keys
   - Use key derivation functions (KDF) for password-based keys
4. **Key Length**: Use recommended minimum lengths
   - AES: 256 bits
   - RSA: 2048 bits (minimum), 3072+ recommended
   - ECDSA: 256 bits (P-256 or Curve25519)

### Algorithm Selection

✅ **Recommended**:
- Symmetric: AES-256-GCM, ChaCha20-Poly1305
- Asymmetric: RSA-2048+ with OAEP, ECC (P-256, Curve25519)
- Hashing: SHA-256, SHA-3
- Signatures: RSA-PSS, ECDSA, Ed25519
- Key Exchange: ECDHE

❌ **Avoid**:
- DES, 3DES, RC4
- MD5, SHA-1 (for security purposes)
- RSA without padding
- ECB mode
- Weak random number generators

### Common Mistakes

1. **Using ECB Mode**: Reveals patterns in data
2. **Reusing IVs/Nonces**: Breaks security of many modes
3. **Not Using Authenticated Encryption**: Use GCM or Poly1305
4. **Rolling Your Own Crypto**: Use established libraries
5. **Weak Random Number Generation**: Use `/dev/urandom` or `secrets` module
6. **Improper Key Derivation**: Use PBKDF2, bcrypt, or Argon2 for passwords

### Password Security

**Key Derivation Functions**:
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# PBKDF2
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,  # OWASP recommendation
)
key = kdf.derive(password)
```

**Recommendations**:
- **bcrypt**: Good for password hashing
- **Argon2**: Winner of password hashing competition
- **PBKDF2**: Widely supported standard
- **scrypt**: Memory-hard function

### Security Considerations

1. **Forward Secrecy**: Use ephemeral keys (DHE/ECDHE)
2. **Side-Channel Resistance**: Be aware of timing attacks
3. **Constant-Time Comparisons**: For signature/MAC verification
4. **Certificate Validation**: Always validate TLS certificates
5. **Input Validation**: Validate all cryptographic inputs

---

## Quick Reference

### Python Libraries

```python
# PyCryptodome - Pure Python crypto library
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# cryptography - Modern, recommended library
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
```

### Command Line Tools

```bash
# Generate RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt/Decrypt with RSA
openssl rsautl -encrypt -pubin -inkey public.pem -in file.txt -out file.enc
openssl rsautl -decrypt -inkey private.pem -in file.enc -out file.txt

# Hash a file
openssl dgst -sha256 file.txt
sha256sum file.txt

# AES encryption
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc
openssl enc -d -aes-256-cbc -in file.enc -out file.txt
```

---

## Resources

### Official Documentation
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

### Books
- "Applied Cryptography" by Bruce Schneier
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "Serious Cryptography" by Jean-Philippe Aumasson

### Online Courses
- Coursera: Cryptography I by Dan Boneh (Stanford)
- Cryptopals Challenges: https://cryptopals.com/

---

## Exam Tips

1. **Understand the fundamentals**: Know the difference between symmetric/asymmetric
2. **Know when to use what**: Don't use asymmetric for bulk encryption
3. **Security properties**: Confidentiality, integrity, authentication, non-repudiation
4. **Common attacks**: MITM, replay attacks, timing attacks
5. **Protocol flows**: Be able to draw TLS handshake, DH key exchange
6. **Mathematical foundations**: Understand modular arithmetic basics
7. **Practical application**: Know how to use libraries securely

**Remember**: The goal isn't to implement crypto from scratch, but to use existing tools correctly and securely!
