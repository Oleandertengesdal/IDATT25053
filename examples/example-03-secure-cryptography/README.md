# Example 3: Secure Cryptography Implementation

## 🎯 Learning Objectives

By completing this example, you will:

1. **Understand** common cryptographic pitfalls
2. **Implement** secure encryption and hashing
3. **Apply** proper key management techniques
4. **Avoid** cryptographic antipatterns
5. **Use** industry-standard libraries correctly

## 📋 Prerequisites

- Basic understanding of cryptography concepts (symmetric/asymmetric encryption, hashing)
- Python 3.8+

**Required Libraries**:
```bash
pip install cryptography
```

**Estimated Time**: 60 minutes

---

## 🔍 Problem Description

### The Scenario

You're building a secure messaging application that needs to:
- Encrypt messages between users
- Store passwords securely
- Sign messages to verify authenticity
- Manage encryption keys safely

### Common Cryptographic Mistakes

1. **Using weak or outdated algorithms** (MD5, SHA1, DES)
2. **Implementing crypto yourself** (rolling your own)
3. **Hardcoding secrets** in source code
4. **Using ECB mode** for block ciphers
5. **Not using authenticated encryption**
6. **Improper key derivation** from passwords
7. **Reusing IVs/nonces**

---

## ⚠️ Vulnerable Implementation

```python
"""
vulnerable_crypto.py

⚠️ VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
Contains multiple cryptographic vulnerabilities!
"""

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import hashlib
import base64

class VulnerableCrypto:
    """
    Demonstrates common cryptographic mistakes.
    DO NOT USE IN PRODUCTION!
    """
    
    # ⚠️ MISTAKE 1: Hardcoded encryption key
    SECRET_KEY = b'this_is_my_secret_key_12345678'
    
    def __init__(self):
        # ⚠️ MISTAKE 2: Using short, weak key
        self.weak_key = b'12345678'  # Only 8 bytes!
    
    def hash_password_insecure(self, password: str) -> str:
        """
        ⚠️ VULNERABLE: Uses MD5 without salt
        
        Problems:
        - MD5 is cryptographically broken
        - No salt means rainbow table attacks work
        - Too fast (allows brute force)
        """
        # ⚠️ MISTAKE 3: MD5 is broken!
        return hashlib.md5(password.encode()).hexdigest()
    
    def encrypt_ecb_mode(self, plaintext: str) -> str:
        """
        ⚠️ VULNERABLE: Uses ECB mode
        
        Problems:
        - ECB reveals patterns in data
        - Same plaintext = same ciphertext
        - No authentication
        """
        # Pad to block size
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + (chr(pad_len) * pad_len)
        
        # ⚠️ MISTAKE 4: ECB mode (Electronic Codebook)
        cipher = AES.new(self.SECRET_KEY[:16], AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded.encode())
        
        return base64.b64encode(ciphertext).decode()
    
    def decrypt_ecb_mode(self, ciphertext_b64: str) -> str:
        """Decrypt ECB mode (insecure)"""
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = AES.new(self.SECRET_KEY[:16], AES.MODE_ECB)
        padded = cipher.decrypt(ciphertext).decode()
        
        # Remove padding
        pad_len = ord(padded[-1])
        return padded[:-pad_len]
    
    def encrypt_with_weak_des(self, plaintext: str) -> str:
        """
        ⚠️ VULNERABLE: Uses DES
        
        Problems:
        - DES has only 56-bit key (easily brute forced)
        - Deprecated since 1999
        """
        # ⚠️ MISTAKE 5: Using DES instead of AES
        cipher = DES.new(self.weak_key, DES.MODE_ECB)
        
        # Pad to 8 bytes
        pad_len = 8 - (len(plaintext) % 8)
        padded = plaintext + (chr(pad_len) * pad_len)
        
        ciphertext = cipher.encrypt(padded.encode())
        return base64.b64encode(ciphertext).decode()
    
    def simple_xor_encrypt(self, plaintext: str, key: str) -> str:
        """
        ⚠️ VULNERABLE: XOR cipher
        
        Problems:
        - Trivial to break with known plaintext
        - Key reuse allows crib dragging
        - No authentication
        """
        # ⚠️ MISTAKE 6: Home-rolled crypto
        result = []
        for i, char in enumerate(plaintext):
            key_char = key[i % len(key)]
            result.append(chr(ord(char) ^ ord(key_char)))
        
        return base64.b64encode(''.join(result).encode()).decode()
    
    def derive_key_insecure(self, password: str) -> bytes:
        """
        ⚠️ VULNERABLE: Weak key derivation
        
        Problems:
        - Simple hash not designed for key derivation
        - No salt
        - Too fast (allows brute force)
        """
        # ⚠️ MISTAKE 7: Not using PBKDF2/Argon2
        return hashlib.sha256(password.encode()).digest()


def demonstrate_vulnerabilities():
    """Show why these implementations are insecure"""
    print("=" * 70)
    print("CRYPTOGRAPHIC VULNERABILITIES DEMONSTRATION")
    print("=" * 70)
    
    crypto = VulnerableCrypto()
    
    # Demo 1: MD5 collision
    print("\n[DEMO 1] MD5 Hash Collision")
    print("-" * 70)
    password1 = "password123"
    password2 = "password123"
    hash1 = crypto.hash_password_insecure(password1)
    hash2 = crypto.hash_password_insecure(password2)
    print(f"Password 1: {password1} → {hash1}")
    print(f"Password 2: {password2} → {hash2}")
    print("⚠️  Same passwords = same hashes (rainbow table attack possible!)")
    
    # Demo 2: ECB mode reveals patterns
    print("\n[DEMO 2] ECB Mode Pattern Leakage")
    print("-" * 70)
    message = "HELLO WORLD HELLO WORLD HELLO WORLD"
    encrypted = crypto.encrypt_ecb_mode(message)
    print(f"Message: {message}")
    print(f"Encrypted: {encrypted}")
    print("⚠️  Repeated 'HELLO WORLD' creates repeated cipher blocks!")
    
    # Demo 3: Weak DES
    print("\n[DEMO 3] Weak DES Encryption")
    print("-" * 70)
    secret = "MySecret"
    des_encrypted = crypto.encrypt_with_weak_des(secret)
    print(f"Secret: {secret}")
    print(f"DES Encrypted: {des_encrypted}")
    print("⚠️  DES uses only 56-bit key (can be brute forced in hours!)")
    
    # Demo 4: XOR weakness
    print("\n[DEMO 4] XOR Cipher Weakness")
    print("-" * 70)
    plaintext = "ATTACK AT DAWN"
    key = "SECRET"
    xor_encrypted = crypto.simple_xor_encrypt(plaintext, key)
    print(f"Plaintext: {plaintext}")
    print(f"XOR Key: {key}")
    print(f"Encrypted: {xor_encrypted}")
    print("⚠️  XOR with short key is trivially broken!")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    demonstrate_vulnerabilities()
```

---

## ✅ Secure Implementation

```python
"""
secure_crypto.py

✅ SECURE CODE - PRODUCTION-READY

Demonstrates proper cryptographic practices using modern algorithms.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64
import secrets
from typing import Tuple, Dict

class SecureCrypto:
    """
    Secure cryptographic operations following best practices.
    
    Security Features:
    - Strong algorithms (AES-256, SHA-256, RSA-2048+)
    - Authenticated encryption (GCM mode)
    - Proper key derivation (PBKDF2)
    - Secure random number generation
    - No hardcoded secrets
    """
    
    def __init__(self):
        """Initialize with secure defaults"""
        self.backend = default_backend()
        
        # Constants for KDF
        self.KDF_ITERATIONS = 100_000  # OWASP recommendation
        self.SALT_LENGTH = 32  # 256 bits
        self.KEY_LENGTH = 32   # 256 bits for AES-256
    
    # =====================================
    # Password Hashing (Argon2/PBKDF2)
    # =====================================
    
    def hash_password_secure(self, password: str) -> Dict[str, str]:
        """
        ✅ SECURE: Hash password with PBKDF2-HMAC-SHA256
        
        Features:
        - Random salt (unique per password)
        - High iteration count (slow = resistant to brute force)
        - Cryptographically secure hash function
        
        Returns:
            Dict with 'hash' and 'salt' (both base64 encoded)
        """
        # Generate random salt
        salt = os.urandom(self.SALT_LENGTH)
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=self.backend
        )
        
        password_hash = kdf.derive(password.encode())
        
        return {
            'hash': base64.b64encode(password_hash).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iterations': self.KDF_ITERATIONS,
            'algorithm': 'PBKDF2-HMAC-SHA256'
        }
    
    def verify_password_secure(self, password: str, stored_hash: str, stored_salt: str) -> bool:
        """
        ✅ SECURE: Verify password against stored hash
        
        Args:
            password: Password to verify
            stored_hash: Base64-encoded stored hash
            stored_salt: Base64-encoded stored salt
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt = base64.b64decode(stored_salt)
            expected_hash = base64.b64decode(stored_hash)
            
            # Derive key from provided password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.KDF_ITERATIONS,
                backend=self.backend
            )
            
            # Verify (will raise exception if wrong)
            kdf.verify(password.encode(), expected_hash)
            return True
            
        except Exception:
            return False
    
    # =====================================
    # Symmetric Encryption (AES-GCM)
    # =====================================
    
    def encrypt_message_secure(self, plaintext: str, password: str) -> Dict[str, str]:
        """
        ✅ SECURE: Encrypt with AES-256-GCM (authenticated encryption)
        
        Features:
        - AES-256 (strong cipher)
        - GCM mode (authenticated encryption - detects tampering)
        - Random IV (unique per message)
        - Key derived from password using PBKDF2
        
        Returns:
            Dict with 'ciphertext', 'iv', 'salt', 'tag' (all base64)
        """
        # Generate random salt and IV
        salt = os.urandom(self.SALT_LENGTH)
        iv = os.urandom(12)  # 96 bits for GCM
        
        # Derive encryption key from password
        key = self._derive_key(password, salt)
        
        # Create cipher in GCM mode (authenticated encryption)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # GCM provides authentication tag
        tag = encryptor.tag
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'salt': base64.b64encode(salt).decode(),
            'tag': base64.b64encode(tag).decode(),
            'algorithm': 'AES-256-GCM'
        }
    
    def decrypt_message_secure(self, encrypted_data: Dict[str, str], password: str) -> str:
        """
        ✅ SECURE: Decrypt AES-GCM encrypted message
        
        Args:
            encrypted_data: Dict from encrypt_message_secure()
            password: Decryption password
            
        Returns:
            Decrypted plaintext
            
        Raises:
            Exception if decryption fails or message was tampered with
        """
        # Decode all components
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        salt = base64.b64decode(encrypted_data['salt'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Derive key
        key = self._derive_key(password, salt)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),  # Tag for authentication
            backend=self.backend
        )
        
        # Decrypt (will raise exception if authentication fails)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    # =====================================
    # High-Level API (Fernet)
    # =====================================
    
    def generate_fernet_key(self) -> str:
        """
        Generate a Fernet encryption key.
        
        Returns:
            Base64-encoded key (store securely!)
        """
        return Fernet.generate_key().decode()
    
    def encrypt_with_fernet(self, plaintext: str, key_b64: str) -> str:
        """
        ✅ SECURE: Encrypt using Fernet (simple authenticated encryption)
        
        Fernet is a high-level symmetric encryption recipe that provides:
        - AES-128 in CBC mode
        - HMAC for authentication
        - Timestamp for expiration
        
        Args:
            plaintext: Data to encrypt
            key_b64: Base64-encoded Fernet key
            
        Returns:
            Base64-encoded ciphertext token
        """
        f = Fernet(key_b64.encode())
        token = f.encrypt(plaintext.encode())
        return token.decode()
    
    def decrypt_with_fernet(self, token: str, key_b64: str, ttl: int = None) -> str:
        """
        ✅ SECURE: Decrypt Fernet token
        
        Args:
            token: Encrypted token
            key_b64: Base64-encoded Fernet key
            ttl: Time-to-live in seconds (optional)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            InvalidToken if decryption fails or token expired
        """
        f = Fernet(key_b64.encode())
        plaintext = f.decrypt(token.encode(), ttl=ttl)
        return plaintext.decode()
    
    # =====================================
    # Asymmetric Encryption (RSA)
    # =====================================
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (2048 minimum, 4096 recommended)
            
        Returns:
            (private_key_pem, public_key_pem)
        """
        from cryptography.hazmat.primitives import serialization
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Get public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return (private_pem, public_pem)
    
    # =====================================
    # Message Authentication (HMAC)
    # =====================================
    
    def create_hmac(self, message: str, key: bytes) -> str:
        """
        ✅ SECURE: Create HMAC for message authentication
        
        Args:
            message: Message to authenticate
            key: Secret key (min 32 bytes)
            
        Returns:
            Base64-encoded HMAC tag
        """
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(message.encode())
        return base64.b64encode(h.finalize()).decode()
    
    def verify_hmac(self, message: str, key: bytes, tag_b64: str) -> bool:
        """
        ✅ SECURE: Verify HMAC tag
        
        Returns:
            True if authentic, False otherwise
        """
        try:
            tag = base64.b64decode(tag_b64)
            h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
            h.update(message.encode())
            h.verify(tag)
            return True
        except Exception:
            return False


def demonstrate_secure_crypto():
    """Demonstrate secure cryptographic operations"""
    print("=" * 70)
    print("SECURE CRYPTOGRAPHY DEMONSTRATION")
    print("=" * 70)
    
    crypto = SecureCrypto()
    
    # Demo 1: Secure password hashing
    print("\n[DEMO 1] Secure Password Hashing")
    print("-" * 70)
    password = "MySecurePassword123!"
    hash_data = crypto.hash_password_secure(password)
    print(f"Password: {password}")
    print(f"Algorithm: {hash_data['algorithm']}")
    print(f"Iterations: {hash_data['iterations']:,}")
    print(f"Salt: {hash_data['salt'][:50]}...")
    print(f"Hash: {hash_data['hash'][:50]}...")
    
    # Verify correct password
    is_valid = crypto.verify_password_secure(password, hash_data['hash'], hash_data['salt'])
    print(f"\n✓ Correct password verified: {is_valid}")
    
    # Verify wrong password
    is_valid = crypto.verify_password_secure("WrongPassword", hash_data['hash'], hash_data['salt'])
    print(f"✓ Wrong password rejected: {not is_valid}")
    
    # Demo 2: Authenticated encryption
    print("\n[DEMO 2] AES-256-GCM Authenticated Encryption")
    print("-" * 70)
    secret_message = "This is a confidential message!"
    encryption_password = "StrongPassword456!"
    
    encrypted = crypto.encrypt_message_secure(secret_message, encryption_password)
    print(f"Plaintext: {secret_message}")
    print(f"Algorithm: {encrypted['algorithm']}")
    print(f"Ciphertext: {encrypted['ciphertext'][:50]}...")
    print(f"IV: {encrypted['iv'][:30]}...")
    print(f"Auth Tag: {encrypted['tag'][:30]}...")
    
    # Decrypt
    decrypted = crypto.decrypt_message_secure(encrypted, encryption_password)
    print(f"\n✓ Decrypted: {decrypted}")
    print(f"✓ Match: {decrypted == secret_message}")
    
    # Try tampering
    print("\n[TAMPERING DETECTION]")
    encrypted_tampered = encrypted.copy()
    encrypted_tampered['ciphertext'] = base64.b64encode(b'X' * 50).decode()
    try:
        crypto.decrypt_message_secure(encrypted_tampered, encryption_password)
        print("✗ Tampering not detected!")
    except Exception:
        print("✓ Tampering detected and rejected!")
    
    # Demo 3: Fernet (high-level API)
    print("\n[DEMO 3] Fernet Symmetric Encryption")
    print("-" * 70)
    fernet_key = crypto.generate_fernet_key()
    message = "Simple encrypted message"
    
    token = crypto.encrypt_with_fernet(message, fernet_key)
    decrypted = crypto.decrypt_with_fernet(token, fernet_key)
    
    print(f"Message: {message}")
    print(f"Token: {token[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"✓ Match: {decrypted == message}")
    
    # Demo 4: HMAC message authentication
    print("\n[DEMO 4] HMAC Message Authentication")
    print("-" * 70)
    message = "Transfer $1000 to account #12345"
    hmac_key = secrets.token_bytes(32)
    
    tag = crypto.create_hmac(message, hmac_key)
    print(f"Message: {message}")
    print(f"HMAC Tag: {tag[:50]}...")
    
    # Verify authentic message
    is_authentic = crypto.verify_hmac(message, hmac_key, tag)
    print(f"\n✓ Authentic message verified: {is_authentic}")
    
    # Verify tampered message
    tampered = "Transfer $9999 to account #99999"
    is_authentic = crypto.verify_hmac(tampered, hmac_key, tag)
    print(f"✓ Tampered message rejected: {not is_authentic}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    demonstrate_secure_crypto()
```

---

## 🎓 Key Takeaways

### Cryptographic Best Practices

✅ **Use Established Libraries**
- `cryptography` (Python)
- Don't implement crypto yourself!

✅ **Use Strong Algorithms**
- **Hashing**: SHA-256, SHA-3
- **Symmetric**: AES-256
- **Asymmetric**: RSA-2048+, ECC
- **KDF**: PBKDF2, Argon2, scrypt

✅ **Use Authenticated Encryption**
- AES-GCM (Galois/Counter Mode)
- ChaCha20-Poly1305
- Never use ECB mode!

✅ **Generate Random Values Securely**
```python
import secrets
random_key = secrets.token_bytes(32)  # ✓ Secure
# NOT: random.randint()  # ✗ Not cryptographically secure
```

✅ **Proper Key Management**
- Never hardcode keys
- Use environment variables or key management systems
- Rotate keys regularly
- Store keys securely (HSM, key vault)

### Common Mistakes

❌ Using MD5 or SHA1 for passwords  
❌ Using ECB mode  
❌ Reusing IVs/nonces  
❌ Hardcoding encryption keys  
❌ Rolling your own crypto  
❌ Using weak key derivation  
❌ Not authenticating encrypted data

---

## 📝 Exercises

### Exercise 1: Fix the Vulnerable Code

Identify and fix all vulnerabilities in this code:

```python
import hashlib

SECRET_KEY = "mykey123"

def encrypt(data):
    return hashlib.md5((data + SECRET_KEY).encode()).hexdigest()
```

### Exercise 2: Implement Secure File Encryption

Create a program that:
1. Encrypts a file with AES-256-GCM
2. Derives key from user password
3. Stores encrypted file with metadata
4. Decrypts and verifies integrity

### Exercise 3: Password Policy

Implement a secure password storage system with:
- PBKDF2 with 100,000 iterations
- Unique salt per password
- Password strength requirements
- Protection against timing attacks

---

## 🔗 Resources

- [Cryptography Library Documentation](https://cryptography.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Guidelines](https://csrc.nist.gov/publications)

---

**Last Updated**: October 14, 2025  
**Author**: IDATT2503 Course Team
