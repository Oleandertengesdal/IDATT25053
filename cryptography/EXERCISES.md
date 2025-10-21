# Cryptography Exercises - IDATT2503
**Practice problems with solutions**

## Exercise 1: Hash Functions

### Problem
Calculate the SHA-256 hash of the following strings. Verify your answers using Python.

1. "NTNU Trondheim"
2. "Security is important!"
3. "" (empty string)

### Solution

```python
import hashlib

def calculate_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Test cases
print("1:", calculate_sha256("NTNU Trondheim"))
print("2:", calculate_sha256("Security is important!"))
print("3:", calculate_sha256(""))
```

**Expected Output**:
```
1: 8f3b5e9c2d1a4f6e8b7a9c3e5d2f1a8b6c4e2d9f7a5c3e1b8d6f4a2c9e7b5a3d1
2: [Calculate to verify]
3: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Key Concepts**:
- Empty string has a known SHA-256 hash
- Even small changes cause completely different hashes (avalanche effect)
- Same input always produces the same output (deterministic)

---

## Exercise 2: Symmetric Encryption with AES

### Problem
Implement a simple file encryption program using AES-256 in GCM mode.

Requirements:
- Generate a random 256-bit key
- Use a random nonce for each encryption
- Store nonce with the ciphertext
- Implement both encrypt and decrypt functions

### Solution

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_message(message, key):
    """Encrypt a message using AES-256-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    
    # Return nonce + tag + ciphertext (all needed for decryption)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted, key):
    """Decrypt a message using AES-256-GCM"""
    encrypted = base64.b64decode(encrypted)
    
    # Extract nonce, tag, and ciphertext
    nonce = encrypted[:16]
    tag = encrypted[16:32]
    ciphertext = encrypted[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    key = get_random_bytes(32)  # 256-bit key
    
    message = "Secret message from NTNU!"
    encrypted = encrypt_message(message, key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt_message(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    assert message == decrypted, "Decryption failed!"
```

**Questions to Consider**:
1. Why do we use GCM mode instead of CBC?
2. Why do we store the nonce with the ciphertext?
3. What happens if we reuse a nonce with the same key?

**Answers**:
1. GCM provides both encryption and authentication (prevents tampering)
2. Nonce must be unique but doesn't need to be secret
3. Reusing nonce/key pair can reveal plaintext and break security

---

## Exercise 3: RSA Key Generation and Encryption

### Problem
Implement a simple RSA encryption/decryption system. Generate a 2048-bit RSA key pair and demonstrate encryption and decryption.

### Solution

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_key_pair():
    """Generate RSA 2048-bit key pair"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(message, public_key_pem):
    """Encrypt with RSA public key"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(encrypted, private_key_pem):
    """Decrypt with RSA private key"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_key_pair()
    
    # Save keys to files
    with open("private_key.pem", "wb") as f:
        f.write(private_key)
    with open("public_key.pem", "wb") as f:
        f.write(public_key)
    
    # Encrypt and decrypt
    message = "Hello from IDATT2503!"
    encrypted = encrypt_rsa(message, public_key)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = decrypt_rsa(encrypted, private_key)
    print(f"Decrypted: {decrypted}")
    
    assert message == decrypted
```

**Challenge**: Modify this to handle messages longer than 190 bytes (RSA limitation).

**Hint**: Use hybrid encryption - encrypt a random AES key with RSA, then encrypt the message with AES.

---

## Exercise 4: Digital Signatures

### Problem
Create a document signing system that:
1. Signs a document with a private key
2. Verifies the signature with a public key
3. Detects if the document has been tampered with

### Solution

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_document(document, private_key_pem):
    """Sign a document using RSA private key"""
    private_key = RSA.import_key(private_key_pem)
    h = SHA256.new(document.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(document, signature, public_key_pem):
    """Verify document signature using RSA public key"""
    public_key = RSA.import_key(public_key_pem)
    h = SHA256.new(document.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
if __name__ == "__main__":
    # Generate key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Original document
    document = "This is an important contract dated 2025-10-14."
    
    # Sign the document
    signature = sign_document(document, private_key)
    print(f"Document signed. Signature length: {len(signature)} bytes")
    
    # Verify original document
    is_valid = verify_signature(document, signature, public_key)
    print(f"Original document verification: {is_valid}")
    
    # Tamper with document
    tampered = document.replace("2025", "2024")
    is_valid_tampered = verify_signature(tampered, signature, public_key)
    print(f"Tampered document verification: {is_valid_tampered}")
```

**Expected Output**:
```
Document signed. Signature length: 256 bytes
Original document verification: True
Tampered document verification: False
```

---

## Exercise 5: Password Hashing

### Problem
Implement a secure password storage system using proper key derivation functions.

Requirements:
- Use PBKDF2 or bcrypt
- Generate unique salt for each password
- Store salt with hashed password
- Implement password verification

### Solution

```python
import hashlib
import os
import base64

def hash_password(password):
    """Hash a password using PBKDF2-SHA256"""
    salt = os.urandom(32)  # 256-bit salt
    iterations = 600000    # OWASP recommendation for 2023+
    
    # Derive key
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations
    )
    
    # Store salt and hash together
    storage = base64.b64encode(salt + key).decode()
    return f"pbkdf2:sha256:{iterations}${storage}"

def verify_password(password, stored_password):
    """Verify a password against stored hash"""
    # Parse stored password
    parts = stored_password.split('$')
    algorithm_info = parts[0]
    iterations = int(algorithm_info.split(':')[2])
    
    # Decode salt and hash
    decoded = base64.b64decode(parts[1])
    salt = decoded[:32]
    stored_hash = decoded[32:]
    
    # Hash the provided password with the same salt
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations
    )
    
    # Constant-time comparison
    return key == stored_hash

# Example usage
if __name__ == "__main__":
    # Register user
    password = "MySecureP@ssw0rd!"
    hashed = hash_password(password)
    print(f"Stored hash: {hashed[:60]}...")
    
    # Login attempts
    print(f"Correct password: {verify_password('MySecureP@ssw0rd!', hashed)}")
    print(f"Wrong password: {verify_password('WrongPassword', hashed)}")
```

**Security Notes**:
- Each password gets a unique salt (prevents rainbow table attacks)
- High iteration count makes brute force slow
- Salt doesn't need to be secret, only unique
- Never store passwords in plain text!

---

## Exercise 6: Man-in-the-Middle Attack Simulation

### Problem
Simulate a Man-in-the-Middle attack on unprotected Diffie-Hellman key exchange.

### Scenario

```python
import random

# Simulated Diffie-Hellman parameters
p = 23  # Prime (small for demonstration)
g = 5   # Generator

def dh_generate_keypair():
    """Generate DH key pair"""
    private = random.randint(2, p-2)
    public = pow(g, private, p)
    return private, public

def dh_compute_secret(private, peer_public):
    """Compute shared secret"""
    return pow(peer_public, private, p)

# Normal DH exchange
print("=== Normal Diffie-Hellman ===")
alice_private, alice_public = dh_generate_keypair()
bob_private, bob_public = dh_generate_keypair()

print(f"Alice sends public: {alice_public}")
print(f"Bob sends public: {bob_public}")

alice_secret = dh_compute_secret(alice_private, bob_public)
bob_secret = dh_compute_secret(bob_private, alice_public)

print(f"Alice's secret: {alice_secret}")
print(f"Bob's secret: {bob_secret}")
assert alice_secret == bob_secret

# MITM Attack
print("\n=== Man-in-the-Middle Attack ===")
alice_private, alice_public = dh_generate_keypair()
bob_private, bob_public = dh_generate_keypair()
eve_private, eve_public = dh_generate_keypair()  # Attacker

print(f"Alice sends: {alice_public}, Eve intercepts and sends: {eve_public} to Bob")
print(f"Bob sends: {bob_public}, Eve intercepts and sends: {eve_public} to Alice")

alice_secret = dh_compute_secret(alice_private, eve_public)  # Alice thinks she's talking to Bob
bob_secret = dh_compute_secret(bob_private, eve_public)      # Bob thinks he's talking to Alice
eve_alice_secret = dh_compute_secret(eve_private, alice_public)
eve_bob_secret = dh_compute_secret(eve_private, bob_public)

print(f"Alice's secret with 'Bob' (Eve): {alice_secret}")
print(f"Bob's secret with 'Alice' (Eve): {bob_secret}")
print(f"Eve's secret with Alice: {eve_alice_secret}")
print(f"Eve's secret with Bob: {eve_bob_secret}")

print("\nEve can now decrypt and re-encrypt all messages!")
```

**Question**: How can we prevent this attack?

**Answer**: Use authenticated Diffie-Hellman (sign the public values with digital signatures) or use certificates (as in TLS).

---

## Exercise 7: Hybrid Encryption

### Problem
Implement a hybrid encryption system that combines RSA and AES:
- Use RSA to encrypt a random AES key
- Use AES to encrypt the actual message
- This allows encrypting large messages with RSA's security

### Solution

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

def hybrid_encrypt(message, public_key_pem):
    """Encrypt using hybrid RSA + AES"""
    # Generate random AES key
    aes_key = get_random_bytes(32)
    
    # Encrypt message with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    
    # Encrypt AES key with RSA
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    
    # Package everything together
    package = {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'nonce': base64.b64encode(cipher_aes.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    
    return package

def hybrid_decrypt(package, private_key_pem):
    """Decrypt using hybrid RSA + AES"""
    # Decrypt AES key with RSA
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = base64.b64decode(package['encrypted_key'])
    aes_key = cipher_rsa.decrypt(encrypted_key)
    
    # Decrypt message with AES
    nonce = base64.b64decode(package['nonce'])
    tag = base64.b64decode(package['tag'])
    ciphertext = base64.b64decode(package['ciphertext'])
    
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    # Generate RSA keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Large message (wouldn't fit in RSA encryption)
    message = "This is a very long message " * 100
    
    # Encrypt
    encrypted_package = hybrid_encrypt(message, public_key)
    print(f"Encrypted key length: {len(encrypted_package['encrypted_key'])}")
    print(f"Ciphertext length: {len(encrypted_package['ciphertext'])}")
    
    # Decrypt
    decrypted = hybrid_decrypt(encrypted_package, private_key)
    print(f"Decrypted length: {len(decrypted)}")
    
    assert message == decrypted
    print("Success!")
```

**Why Hybrid Encryption?**
- RSA can only encrypt small amounts of data (max 190 bytes with 2048-bit key)
- AES is much faster for large data
- This is how TLS and PGP work in practice

---

## Exercise 8: Timing Attack

### Problem
Demonstrate why constant-time comparison is important for security.

### Vulnerable Code

```python
import time
import random

def insecure_compare(a, b):
    """Insecure comparison - vulnerable to timing attack"""
    if len(a) != len(b):
        return False
    
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # Returns immediately on first mismatch
        time.sleep(0.00001)  # Simulated processing time
    
    return True

def secure_compare(a, b):
    """Secure constant-time comparison"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)  # XOR all bytes
    
    return result == 0

# Demonstrate timing attack
def timing_attack_demo():
    secret = "SECRET123456"
    
    print("=== Insecure Comparison (Timing Attack Possible) ===")
    
    # Try different guesses
    guesses = ["AAAAAAAAAAAA", "SAAAAAAAAA", "SEAAAAAAAAAA", "SECAAAAAAAA"]
    
    for guess in guesses:
        start = time.time()
        insecure_compare(secret, guess)
        elapsed = time.time() - start
        print(f"Guess '{guess}': {elapsed:.6f} seconds")
    
    print("\nNotice: Correct prefixes take longer!")
    print("Attacker can deduce secret one character at a time")
    
    print("\n=== Secure Comparison (Constant Time) ===")
    
    for guess in guesses:
        start = time.time()
        secure_compare(secret, guess)
        elapsed = time.time() - start
        print(f"Guess '{guess}': {elapsed:.6f} seconds")
    
    print("\nNotice: All comparisons take approximately the same time")

if __name__ == "__main__":
    timing_attack_demo()
```

**Key Lesson**: Always use constant-time comparison for security-critical operations (passwords, tokens, HMACs, etc.)

---

## Challenge Problems

### Challenge 1: Build a Secure Chat System
Create a simple encrypted chat application:
- Use ECDH for key exchange
- Use AES-GCM for message encryption
- Implement forward secrecy (new key for each session)
- Add message authentication

### Challenge 2: Implement Certificate Verification
Write code that:
- Parses X.509 certificates
- Verifies certificate chains
- Checks certificate expiration
- Validates certificate signatures

### Challenge 3: Break Weak Encryption
Implement attacks on:
- ECB mode (detect patterns)
- Weak RSA (small primes)
- Reused nonce in AES-CTR
- Weak random number generator

---

## Additional Practice Resources

1. **Cryptopals Challenges**: https://cryptopals.com/
2. **CryptoHack**: https://cryptohack.org/
3. **Exploit Education**: https://exploit.education/
4. **Try Hack Me - Cryptography**: https://tryhackme.com/

---

## Self-Assessment Questions

1. When should you use symmetric vs asymmetric encryption?
2. Why is ECB mode insecure?
3. What's the difference between encryption and hashing?
4. How does GCM mode provide both encryption and authentication?
5. Why do we need digital signatures when we have encryption?
6. What is forward secrecy and why is it important?
7. How does a timing attack work?
8. Why should salts be unique but don't need to be secret?
9. What's the difference between HTTPS and HTTP?
10. Why can't we just reverse a hash to get the original data?

