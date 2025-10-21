# Lab 2: Applied Cryptography

## 📋 Lab Information

**Duration**: 4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Basic cryptography concepts, Python programming  
**Learning Outcomes**: LO3, LO7, LO8

---

## 🎯 Learning Objectives

By completing this lab, you will be able to:

1. Implement secure password hashing with salt and key derivation functions
2. Use symmetric encryption (AES-GCM) correctly for data protection
3. Apply asymmetric encryption (RSA) for key exchange and digital signatures
4. Implement message authentication codes (HMAC) for integrity verification
5. Avoid common cryptographic mistakes

---

## 📚 Background

Cryptography is essential for protecting data confidentiality, integrity, and authenticity. However, incorrect implementations can be worse than no encryption at all. This lab focuses on using proven cryptographic libraries correctly rather than implementing algorithms from scratch.

**Key Principles**:
- **Don't roll your own crypto**: Use established libraries
- **Use authenticated encryption**: Ensure both confidentiality and integrity
- **Key management matters**: Protect and rotate keys properly
- **Salt everything**: Prevent rainbow table attacks
- **Use strong algorithms**: AES-256, RSA-2048+, SHA-256+

---

## 🔧 Setup

### Prerequisites

- Python 3.8+
- Docker Desktop
- Basic understanding of cryptographic concepts

### Installation

1. **Navigate to lab directory**:
```bash
cd labs/lab-02-cryptography
```

2. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Verify installation**:
```bash
python -c "from cryptography.fernet import Fernet; print('Cryptography library installed successfully')"
```

---

## 📝 Lab Tasks

### Task 1: Secure Password Storage (45 minutes)

**Objective**: Implement a secure password storage system using PBKDF2.

#### Background

Storing passwords in plaintext or with simple hashing (MD5, SHA1) is insecure:
- Rainbow tables can crack unsalted hashes instantly
- Fast hashing algorithms enable brute force attacks
- Same password = same hash (no salt)

**Solution**: Use key derivation functions (KDF) with salt and high iteration counts.

#### Step 1: Understand Insecure Hashing

Examine `vulnerable/password_insecure.py`:

```python
import hashlib

class InsecurePasswordManager:
    def hash_password(self, password):
        # ⚠️ INSECURE: MD5 without salt
        return hashlib.md5(password.encode()).hexdigest()
    
    def verify_password(self, password, hash):
        return self.hash_password(password) == hash
```

**Problems**:
1. MD5 is cryptographically broken
2. No salt (rainbow tables work)
3. Too fast (enables brute force)

#### Step 2: Implement Secure Password Hashing

Complete `secure/password_secure.py`:

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

class SecurePasswordManager:
    """
    Secure password storage using PBKDF2-HMAC-SHA256.
    """
    
    def __init__(self):
        self.iterations = 100_000  # OWASP recommendation
        self.key_length = 32  # 256 bits
        self.salt_length = 32  # 256 bits
    
    def hash_password(self, password: str) -> dict:
        """
        Hash a password securely.
        
        Returns:
            dict: Contains 'hash', 'salt', 'iterations'
        """
        # TODO: Implement secure password hashing
        
        # Step 1: Generate random salt
        salt = os.urandom(self.salt_length)
        
        # Step 2: Create PBKDF2 instance
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        
        # Step 3: Derive key from password
        key = kdf.derive(password.encode())
        
        # Step 4: Return hash data (store these in database)
        return {
            'hash': base64.b64encode(key).decode(),
            'salt': base64.b64encode(salt).decode(),
            'iterations': self.iterations,
            'algorithm': 'PBKDF2-HMAC-SHA256'
        }
    
    def verify_password(self, password: str, stored_data: dict) -> bool:
        """
        Verify a password against stored hash.
        
        Args:
            password: Password to verify
            stored_data: Dict from hash_password()
            
        Returns:
            True if password matches, False otherwise
        """
        # TODO: Implement password verification
        
        try:
            # Decode stored values
            salt = base64.b64decode(stored_data['salt'])
            stored_hash = base64.b64decode(stored_data['hash'])
            
            # Recreate KDF with same parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=stored_data['iterations'],
                backend=default_backend()
            )
            
            # Verify (raises exception if wrong)
            kdf.verify(password.encode(), stored_hash)
            return True
            
        except Exception:
            return False
```

#### Step 3: Test Password Security

Run tests:
```bash
pytest tests/test_password.py -v
```

**Test Cases**:
- ✓ Same password produces different hashes (unique salts)
- ✓ Correct password verification succeeds
- ✓ Wrong password verification fails
- ✓ Hash is sufficiently slow (100,000+ iterations)

#### Step 4: Benchmark Performance

Run benchmark:
```bash
python benchmark_passwords.py
```

Expected output:
```
MD5:    1,000,000 hashes/sec (INSECURE)
PBKDF2:    10 hashes/sec (Secure - slow is good!)
```

---

### Task 2: Symmetric Encryption (AES-GCM) (45 minutes)

**Objective**: Encrypt and decrypt messages using AES-256-GCM.

#### Background

**AES-GCM** (Galois/Counter Mode) provides:
- **Confidentiality**: Encrypted data is unreadable
- **Authenticity**: Detects tampering (includes authentication tag)
- **Performance**: Fast, hardware-accelerated

**Key Concepts**:
- **IV (Initialization Vector)**: Random value, unique per message
- **Authentication Tag**: Cryptographic checksum to detect tampering
- **Never reuse IV**: Each encryption must use unique IV

#### Step 1: Understand Insecure Encryption

Examine `vulnerable/encryption_insecure.py`:

```python
from Crypto.Cipher import AES

class InsecureEncryption:
    def __init__(self):
        # ⚠️ HARDCODED KEY
        self.key = b'hardcoded_key123'
    
    def encrypt(self, plaintext):
        # ⚠️ ECB MODE (reveals patterns)
        cipher = AES.new(self.key, AES.MODE_ECB)
        # ⚠️ NO AUTHENTICATION
        return cipher.encrypt(plaintext)
```

**Problems**:
1. Hardcoded key (never do this!)
2. ECB mode reveals patterns in data
3. No authentication (tampering undetected)
4. No IV (not needed for ECB but would be reused anyway)

#### Step 2: Implement Secure Encryption

Complete `secure/encryption_secure.py`:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

class SecureEncryption:
    """
    AES-256-GCM authenticated encryption.
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.key_length = 32  # 256 bits for AES-256
    
    def encrypt_message(self, plaintext: str, password: str) -> dict:
        """
        Encrypt a message using AES-256-GCM.
        
        Args:
            plaintext: Message to encrypt
            password: Encryption password
            
        Returns:
            dict: Contains ciphertext, iv, salt, tag
        """
        # TODO: Implement AES-GCM encryption
        
        # Step 1: Generate random salt and IV
        salt = os.urandom(32)
        iv = os.urandom(12)  # 96 bits for GCM
        
        # Step 2: Derive key from password
        key = self._derive_key(password, salt)
        
        # Step 3: Create cipher in GCM mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        
        # Step 4: Encrypt
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Step 5: Get authentication tag
        tag = encryptor.tag
        
        # Step 6: Return all components (all needed for decryption)
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'salt': base64.b64encode(salt).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    
    def decrypt_message(self, encrypted_data: dict, password: str) -> str:
        """
        Decrypt an AES-GCM encrypted message.
        
        Args:
            encrypted_data: Dict from encrypt_message()
            password: Decryption password
            
        Returns:
            Decrypted plaintext
            
        Raises:
            Exception: If decryption fails or data was tampered
        """
        # TODO: Implement AES-GCM decryption
        
        # Step 1: Decode all components
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        salt = base64.b64decode(encrypted_data['salt'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Step 2: Derive key
        key = self._derive_key(password, salt)
        
        # Step 3: Create cipher with tag for authentication
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        
        # Step 4: Decrypt (will raise exception if authentication fails)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
```

#### Step 3: Test Encryption

```bash
pytest tests/test_encryption.py -v
```

**Test Cases**:
- ✓ Encryption produces different ciphertexts (unique IVs)
- ✓ Decryption with correct password succeeds
- ✓ Decryption with wrong password fails
- ✓ Tampering detection works (authentication tag)

#### Step 4: Test Tampering Detection

Run tampering test:
```bash
python test_tampering.py
```

Expected behavior:
- Modifying ciphertext → Decryption fails
- Modifying IV → Decryption fails
- Modifying tag → Decryption fails

---

### Task 3: Asymmetric Encryption (RSA) (45 minutes)

**Objective**: Implement public-key cryptography for key exchange and digital signatures.

#### Background

**RSA** enables:
- **Public-key encryption**: Encrypt with public key, decrypt with private key
- **Digital signatures**: Sign with private key, verify with public key
- **Key exchange**: Safely share symmetric keys

**Key Sizes**:
- Minimum: 2048 bits
- Recommended: 4096 bits
- Stronger: Use ECC (Elliptic Curve Cryptography)

#### Step 1: Generate RSA Key Pair

Complete `secure/rsa_crypto.py`:

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class RSACrypto:
    """
    RSA public-key cryptography implementation.
    """
    
    def generate_keypair(self, key_size=2048):
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (2048 or 4096)
            
        Returns:
            (private_key, public_key) objects
        """
        # TODO: Generate RSA key pair
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard value
            key_size=key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def encrypt_with_public_key(self, public_key, plaintext: str) -> bytes:
        """
        Encrypt data with public key.
        
        Args:
            public_key: RSA public key
            plaintext: Data to encrypt
            
        Returns:
            Encrypted bytes
        """
        # TODO: Implement RSA encryption
        
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext
    
    def decrypt_with_private_key(self, private_key, ciphertext: bytes) -> str:
        """
        Decrypt data with private key.
        
        Args:
            private_key: RSA private key
            ciphertext: Encrypted bytes
            
        Returns:
            Decrypted plaintext
        """
        # TODO: Implement RSA decryption
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode()
    
    def sign_message(self, private_key, message: str) -> bytes:
        """
        Create digital signature.
        
        Args:
            private_key: RSA private key
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        # TODO: Implement digital signature
        
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, public_key, message: str, signature: bytes) -> bool:
        """
        Verify digital signature.
        
        Args:
            public_key: RSA public key
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        # TODO: Implement signature verification
        
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
```

#### Step 2: Test RSA Operations

```bash
pytest tests/test_rsa.py -v
```

**Test Cases**:
- ✓ Key generation produces valid key pair
- ✓ Encryption with public key works
- ✓ Decryption with private key works
- ✓ Digital signature creation succeeds
- ✓ Signature verification with correct key succeeds
- ✓ Signature verification with wrong key fails

---

### Task 4: Message Authentication (HMAC) (30 minutes)

**Objective**: Implement message authentication codes to detect tampering.

#### Background

**HMAC** (Hash-based Message Authentication Code):
- Verifies message integrity
- Verifies message authenticity (only holder of secret key can create valid HMAC)
- Uses cryptographic hash function (SHA-256)

**Use Cases**:
- API authentication
- Cookie integrity
- Message verification

#### Step 1: Implement HMAC

Complete `secure/hmac_auth.py`:

```python
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class HMACAuth:
    """
    HMAC-based message authentication.
    """
    
    def __init__(self, secret_key: bytes = None):
        """
        Initialize with secret key.
        
        Args:
            secret_key: Secret key (min 32 bytes). Generated if not provided.
        """
        if secret_key is None:
            secret_key = secrets.token_bytes(32)
        
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 bytes")
        
        self.secret_key = secret_key
        self.backend = default_backend()
    
    def create_hmac(self, message: str) -> str:
        """
        Create HMAC for message.
        
        Args:
            message: Message to authenticate
            
        Returns:
            Base64-encoded HMAC tag
        """
        # TODO: Implement HMAC creation
        
        h = hmac.HMAC(self.secret_key, hashes.SHA256(), backend=self.backend)
        h.update(message.encode())
        tag = h.finalize()
        
        return base64.b64encode(tag).decode()
    
    def verify_hmac(self, message: str, tag: str) -> bool:
        """
        Verify HMAC tag.
        
        Args:
            message: Original message
            tag: Base64-encoded HMAC tag
            
        Returns:
            True if authentic, False otherwise
        """
        # TODO: Implement HMAC verification
        
        try:
            expected_tag = base64.b64decode(tag)
            
            h = hmac.HMAC(self.secret_key, hashes.SHA256(), backend=self.backend)
            h.update(message.encode())
            h.verify(expected_tag)
            
            return True
        except Exception:
            return False
```

#### Step 2: Test HMAC

```bash
pytest tests/test_hmac.py -v
```

---

### Task 5: Integration - Secure Messaging System (45 minutes)

**Objective**: Build a complete secure messaging system combining all techniques.

#### Requirements

Create `secure_messenger.py` that:

1. **User Registration**:
   - Hash passwords with PBKDF2
   - Generate RSA key pairs for each user
   - Store public keys, never store plaintext passwords

2. **Send Message**:
   - Generate random AES key
   - Encrypt message with AES-GCM
   - Encrypt AES key with recipient's RSA public key
   - Sign entire message with sender's RSA private key
   - Send: encrypted_message + encrypted_key + signature

3. **Receive Message**:
   - Verify signature with sender's public key
   - Decrypt AES key with recipient's RSA private key
   - Decrypt message with AES key
   - Verify message integrity

#### Implementation Template

```python
class SecureMessenger:
    def __init__(self):
        self.password_manager = SecurePasswordManager()
        self.rsa_crypto = RSACrypto()
        self.encryption = SecureEncryption()
        self.users = {}  # username -> user_data
    
    def register_user(self, username, password):
        """Register new user with password and key pair."""
        # TODO: Implement user registration
        pass
    
    def send_message(self, sender, recipient, message, sender_password):
        """Send encrypted and signed message."""
        # TODO: Implement message sending
        pass
    
    def receive_message(self, recipient, encrypted_package, recipient_password):
        """Receive and decrypt message."""
        # TODO: Implement message receiving
        pass
```

#### Test Integration

```bash
pytest tests/test_integration.py -v
```

---

## 📊 Lab Report

### Requirements

Submit a lab report (PDF, maximum 8 pages):

1. **Password Security** (1.5 pages)
   - Implementation details
   - Performance benchmarks
   - Security analysis

2. **Symmetric Encryption** (1.5 pages)
   - AES-GCM implementation
   - Tampering detection results
   - Key derivation approach

3. **Asymmetric Cryptography** (2 pages)
   - RSA implementation
   - Key management strategy
   - Digital signatures

4. **Integration** (2 pages)
   - Secure messenger design
   - Security properties achieved
   - Test results

5. **Reflection** (1 page)
   - Challenges faced
   - Lessons learned
   - Real-world applications

### Grading Rubric

| Criterion | Points |
|-----------|--------|
| Password Hashing (PBKDF2) | 15 |
| Symmetric Encryption (AES-GCM) | 20 |
| Asymmetric Encryption (RSA) | 20 |
| Message Authentication (HMAC) | 15 |
| Integration (Secure Messenger) | 20 |
| Report Quality | 10 |
| **Total** | **100** |

**Pass Requirement**: Minimum 70 points

---

## 🔍 Common Mistakes to Avoid

❌ **Hardcoding keys** in source code  
❌ **Reusing IVs/nonces** across encryptions  
❌ **Using ECB mode** for block ciphers  
❌ **Ignoring authentication tags** (tampering detection)  
❌ **Weak key derivation** from passwords  
❌ **Implementing crypto algorithms** yourself  
❌ **Using deprecated algorithms** (MD5, SHA1, DES)  

---

## 📚 Resources

- [Cryptography Library Documentation](https://cryptography.io/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/Projects/cryptographic-standards-and-guidelines)

---

## 📤 Submission

**Deadline**: Week 12  
**Submit**: Blackboard (source code + lab report PDF)

```bash
git add secure/ tests/ lab_report.pdf
git commit -m "Lab 2: Cryptography implementation"
git push origin lab-02-submission
```

---

**Lab Created**: October 14, 2025  
**Version**: 1.0  
**Estimated Time**: 4-5 hours
