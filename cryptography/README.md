# Cryptography Resources for IDATT2503
**NTNU Trondheim - Security in Software Systems**

Welcome to your comprehensive cryptography learning materials! This directory contains everything you need to master cryptography for the course.

## 📚 Contents

### 1. [Cryptography Guide](./CRYPTOGRAPHY_GUIDE.md)
Complete reference covering:
- Symmetric & Asymmetric Encryption
- Hash Functions & MACs
- Digital Signatures
- Key Exchange Protocols
- TLS/SSL and Common Protocols
- Best Practices and Security Guidelines

### 2. [Exercises](./EXERCISES.md)
Hands-on practice problems with solutions:
- Exercise 1: Hash Functions
- Exercise 2: AES Symmetric Encryption
- Exercise 3: RSA Encryption/Decryption
- Exercise 4: Digital Signatures
- Exercise 5: Password Hashing
- Exercise 6: MITM Attack Simulation
- Exercise 7: Hybrid Encryption
- Exercise 8: Timing Attacks
- Challenge Problems

### 3. [Attacks & Vulnerabilities](./ATTACKS_AND_VULNERABILITIES.md)
Security attack vectors and defenses:
- Common Cryptographic Attacks
- Implementation Vulnerabilities
- Protocol Attacks
- Side-Channel Attacks
- Real-world Examples

### 4. [Examples Directory](./examples/)
Working Python implementations:
- `advanced_aes.py` - AES encryption in multiple modes
- `advanced_rsa.py` - RSA encryption and digital signatures
- Additional practical examples

---

## 🚀 Quick Start

### Prerequisites

Install required Python packages:

```bash
# Using pip
pip install pycryptodome cryptography

# Or using conda
conda install -c conda-forge pycryptodome cryptography
```

### Running Examples

```bash
cd cryptografi/examples

# Run AES examples
python advanced_aes.py

# Run RSA examples
python advanced_rsa.py
```

---

## 📖 Study Path

### Week 1: Foundations
1. Read introduction and symmetric encryption sections
2. Complete Exercises 1-2 (Hash Functions & AES)
3. Run `advanced_aes.py` examples

### Week 2: Asymmetric Cryptography
1. Study asymmetric encryption and digital signatures
2. Complete Exercises 3-4 (RSA & Signatures)
3. Run `advanced_rsa.py` examples

### Week 3: Security & Attacks
1. Read Attacks & Vulnerabilities guide
2. Complete Exercises 5-8
3. Work on challenge problems

### Week 4: Protocols & Practice
1. Study TLS, key exchange, and protocols
2. Review best practices
3. Build a secure application project

---

## 🎯 Exam Preparation

### Key Topics to Master

**Theory**:
- [ ] Difference between symmetric and asymmetric encryption
- [ ] How hash functions work and their properties
- [ ] Digital signature process (sign & verify)
- [ ] Diffie-Hellman key exchange
- [ ] TLS handshake process
- [ ] Common attacks and defenses

**Practical**:
- [ ] When to use which encryption type
- [ ] Proper key management
- [ ] Choosing appropriate algorithms
- [ ] Identifying security vulnerabilities
- [ ] Using crypto libraries correctly

### Practice Questions

1. **Why can't we use RSA to encrypt large files directly?**
   <details>
   <summary>Answer</summary>
   RSA can only encrypt data smaller than the key size (minus padding). For 2048-bit RSA, maximum is ~190 bytes. Solution: Use hybrid encryption (RSA for key, AES for data).
   </details>

2. **What's wrong with using ECB mode for encryption?**
   <details>
   <summary>Answer</summary>
   ECB encrypts identical plaintext blocks to identical ciphertext blocks, revealing patterns in the data. Always use CBC, CTR, or GCM modes.
   </details>

3. **Why do we need both encryption and digital signatures?**
   <details>
   <summary>Answer</summary>
   Encryption provides confidentiality (only intended recipient can read). Digital signatures provide authenticity and integrity (verifies sender and detects tampering). Both are needed for complete security.
   </details>

---

## 🔧 Useful Tools

### Command Line Tools

```bash
# Generate RSA keys
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Hash a file
sha256sum file.txt
openssl dgst -sha256 file.txt

# Encrypt/Decrypt with AES
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc
openssl enc -d -aes-256-cbc -in file.enc -out file.txt

# Generate random data
openssl rand -hex 32  # 256-bit random value
```

### Python Quick Reference

```python
# === Hashing ===
import hashlib
hash_value = hashlib.sha256(b"data").hexdigest()

# === AES Symmetric Encryption ===
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # 256-bit
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(b"plaintext")

# === RSA Asymmetric Encryption ===
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
public_key = key.publickey()

cipher = PKCS1_OAEP.new(public_key)
encrypted = cipher.encrypt(b"secret")

# === Digital Signature ===
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

h = SHA256.new(b"message")
signature = pkcs1_15.new(private_key).sign(h)

# Verify
pkcs1_15.new(public_key).verify(h, signature)

# === Password Hashing ===
import hashlib
import os

salt = os.urandom(32)
key = hashlib.pbkdf2_hmac('sha256', b'password', salt, 600000)
```

---

## 📝 Cheat Sheet

### Algorithm Quick Reference

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Symmetric Encryption | AES-256-GCM | 256 bits | Recommended |
| Asymmetric Encryption | RSA | 2048+ bits | Or ECC-256 |
| Hashing | SHA-256 | - | Or SHA-3 |
| Password Hashing | Argon2/bcrypt | - | High iterations |
| Digital Signatures | RSA-PSS/ECDSA | 2048+/256 bits | With proper padding |
| Key Exchange | ECDHE | 256 bits | For forward secrecy |

### Security Decision Tree

```
Need encryption?
├─ Small data (< 190 bytes)?
│  └─ RSA-2048 with OAEP
└─ Large data?
   └─ AES-256-GCM (or hybrid: RSA + AES)

Need integrity only?
└─ HMAC-SHA256

Need authentication?
└─ Digital signature (RSA-PSS or ECDSA)

Need password storage?
└─ Argon2, bcrypt, or PBKDF2 (600k+ iterations)

Need secure communication?
└─ TLS 1.3
```

---

## 🎓 Additional Resources

### Online Courses
- [Cryptography I - Stanford (Coursera)](https://www.coursera.org/learn/crypto)
- [Applied Cryptography - Udacity](https://www.udacity.com/course/applied-cryptography--cs387)

### Books
- "Applied Cryptography" by Bruce Schneier
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "Serious Cryptography" by Jean-Philippe Aumasson

### Practice Platforms
- [Cryptopals Challenges](https://cryptopals.com/)
- [CryptoHack](https://cryptohack.org/)
- [OverTheWire - Krypton](https://overthewire.org/wargames/krypton/)

### Documentation
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [Python cryptography library docs](https://cryptography.io/)

---

## 🤝 Contributing

Found an error or want to add more examples? Feel free to:
1. Create an issue describing the problem/suggestion
2. Submit a pull request with improvements
3. Share additional resources or exercises

---

## ⚠️ Important Notes

### Security Warnings

1. **Never use these examples in production without review**
2. **Always use established crypto libraries** (don't implement your own)
3. **Keep dependencies updated** for security patches
4. **Get security review** for critical applications
5. **Follow principle of least privilege**

### Learning Philosophy

> "The goal is not to become a cryptographer, but to use cryptography correctly."

Focus on:
- Understanding when to use which tool
- Recognizing common mistakes
- Following security best practices
- Knowing when to ask for expert help

---

## 📧 Contact

For questions about course material:
- Check Blackboard for course forum
- Attend office hours
- Contact your TA or professor

For security vulnerabilities in examples:
- Report responsibly
- Don't publicize before fix

---

## 📄 License

These materials are created for educational purposes for IDATT2503 at NTNU Trondheim.

Examples use:
- PyCryptodome library (BSD-style license)
- cryptography library (Apache 2.0/BSD)

---

**Good luck with your studies! 🔐**

Remember: Security is not a product, but a process. Stay curious, stay vigilant!
