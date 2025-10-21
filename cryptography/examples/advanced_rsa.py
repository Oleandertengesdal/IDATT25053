"""
RSA Encryption and Digital Signatures Example for IDATT2503
Demonstrates key generation, encryption, decryption, and signing
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256, SHA512
import base64
import os


class RSAManager:
    """RSA encryption and signing manager"""
    
    def __init__(self, key_size=2048):
        """Generate new RSA key pair"""
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
        print(f"Generated {key_size}-bit RSA key pair")
    
    def export_keys(self, private_file="private_key.pem", public_file="public_key.pem"):
        """Export keys to PEM files"""
        # Export private key (keep this secret!)
        with open(private_file, 'wb') as f:
            f.write(self.key.export_key('PEM'))
        
        # Export public key (can be shared)
        with open(public_file, 'wb') as f:
            f.write(self.public_key.export_key('PEM'))
        
        print(f"✓ Saved private key to {private_file}")
        print(f"✓ Saved public key to {public_file}")
    
    @staticmethod
    def load_private_key(filename):
        """Load private key from file"""
        with open(filename, 'rb') as f:
            key = RSA.import_key(f.read())
        manager = RSAManager.__new__(RSAManager)
        manager.key = key
        manager.public_key = key.publickey()
        return manager
    
    @staticmethod
    def load_public_key(filename):
        """Load public key from file"""
        with open(filename, 'rb') as f:
            return RSA.import_key(f.read())
    
    def encrypt(self, message):
        """
        Encrypt a message with public key
        Note: RSA can only encrypt small messages (max ~190 bytes for 2048-bit key)
        """
        if isinstance(message, str):
            message = message.encode()
        
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted = cipher.encrypt(message)
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted):
        """Decrypt a message with private key"""
        encrypted = base64.b64decode(encrypted)
        cipher = PKCS1_OAEP.new(self.key)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()
    
    def sign(self, message, hash_algo=SHA256):
        """Create digital signature of message"""
        if isinstance(message, str):
            message = message.encode()
        
        h = hash_algo.new(message)
        signature = pkcs1_15.new(self.key).sign(h)
        return base64.b64encode(signature).decode()
    
    def verify(self, message, signature, public_key=None, hash_algo=SHA256):
        """Verify digital signature"""
        if isinstance(message, str):
            message = message.encode()
        
        signature = base64.b64decode(signature)
        h = hash_algo.new(message)
        
        key_to_use = public_key if public_key else self.public_key
        
        try:
            pkcs1_15.new(key_to_use).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def sign_pss(self, message, hash_algo=SHA256):
        """
        Create PSS digital signature (more secure than PKCS#1 v1.5)
        PSS = Probabilistic Signature Scheme
        """
        if isinstance(message, str):
            message = message.encode()
        
        h = hash_algo.new(message)
        signature = pss.new(self.key).sign(h)
        return base64.b64encode(signature).decode()
    
    def verify_pss(self, message, signature, public_key=None, hash_algo=SHA256):
        """Verify PSS digital signature"""
        if isinstance(message, str):
            message = message.encode()
        
        signature = base64.b64decode(signature)
        h = hash_algo.new(message)
        
        key_to_use = public_key if public_key else self.public_key
        
        try:
            pss.new(key_to_use).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


def demonstrate_encryption():
    """Demonstrate RSA encryption and decryption"""
    
    print("=" * 70)
    print("RSA Encryption/Decryption Demonstration")
    print("=" * 70)
    
    # Generate keys
    rsa = RSAManager(2048)
    
    # Encrypt short message
    message = "Secret message from NTNU!"
    print(f"\nOriginal message: {message}")
    
    encrypted = rsa.encrypt(message)
    print(f"Encrypted (base64): {encrypted[:50]}...")
    
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted message: {decrypted}")
    
    print(f"\n✓ Encryption successful: {message == decrypted}")


def demonstrate_digital_signatures():
    """Demonstrate digital signatures"""
    
    print("\n" + "=" * 70)
    print("Digital Signatures Demonstration")
    print("=" * 70)
    
    # Generate keys
    rsa = RSAManager(2048)
    
    # Document to sign
    document = "This is an important contract dated 2025-10-14."
    print(f"\nDocument: {document}")
    
    # Sign document
    signature = rsa.sign(document)
    print(f"\nSignature (base64): {signature[:50]}...")
    
    # Verify signature
    is_valid = rsa.verify(document, signature)
    print(f"✓ Signature valid: {is_valid}")
    
    # Try to verify tampered document
    tampered = document.replace("2025", "2024")
    is_valid_tampered = rsa.verify(tampered, signature)
    print(f"✗ Tampered document valid: {is_valid_tampered}")


def demonstrate_key_exchange():
    """Demonstrate secure key exchange scenario"""
    
    print("\n" + "=" * 70)
    print("Secure Communication Scenario")
    print("=" * 70)
    
    # Alice and Bob generate their own key pairs
    print("\n1. Alice and Bob generate key pairs")
    alice = RSAManager(2048)
    bob = RSAManager(2048)
    
    # They exchange public keys
    print("2. Alice and Bob exchange public keys")
    
    # Alice sends encrypted message to Bob
    print("\n3. Alice encrypts message with Bob's public key")
    message = "Hello Bob! Let's meet at 15:00."
    
    # Create a new cipher with Bob's public key
    cipher = PKCS1_OAEP.new(bob.public_key)
    encrypted = cipher.encrypt(message.encode())
    encrypted_b64 = base64.b64encode(encrypted).decode()
    
    print(f"   Message: {message}")
    print(f"   Encrypted: {encrypted_b64[:50]}...")
    
    # Bob decrypts the message
    print("\n4. Bob decrypts with his private key")
    decrypted = bob.decrypt(encrypted_b64)
    print(f"   Decrypted: {decrypted}")
    
    # Alice also signs the message to prove authenticity
    print("\n5. Alice signs the message")
    signature = alice.sign(message)
    print(f"   Signature: {signature[:50]}...")
    
    # Bob verifies the signature with Alice's public key
    print("\n6. Bob verifies signature with Alice's public key")
    is_valid = alice.verify(message, signature, alice.public_key)
    print(f"   ✓ Signature valid: {is_valid}")
    
    print("\n✓ Secure communication established!")
    print("   - Confidentiality: Only Bob can decrypt")
    print("   - Authentication: Bob knows it's from Alice")
    print("   - Integrity: Message hasn't been tampered with")


def demonstrate_key_sizes():
    """Demonstrate different RSA key sizes"""
    
    print("\n" + "=" * 70)
    print("RSA Key Sizes and Performance")
    print("=" * 70)
    
    import time
    
    message = "Test message"
    key_sizes = [1024, 2048, 3072, 4096]
    
    print(f"\n{'Key Size':<12} {'Gen Time':<12} {'Enc Time':<12} {'Security'}")
    print("-" * 70)
    
    for size in key_sizes:
        # Measure key generation time
        start = time.time()
        rsa = RSAManager(size)
        gen_time = time.time() - start
        
        # Measure encryption time
        start = time.time()
        encrypted = rsa.encrypt(message)
        enc_time = time.time() - start
        
        # Security level
        if size < 2048:
            security = "⚠️  Weak (deprecated)"
        elif size == 2048:
            security = "✓ Minimum"
        elif size == 3072:
            security = "✓✓ Recommended"
        else:
            security = "✓✓✓ High security"
        
        print(f"{size:<12} {gen_time:<12.4f} {enc_time:<12.6f} {security}")


def demonstrate_pss_signatures():
    """Demonstrate PSS signatures (more secure)"""
    
    print("\n" + "=" * 70)
    print("PSS Signatures (Probabilistic Signature Scheme)")
    print("=" * 70)
    
    rsa = RSAManager(2048)
    
    message = "Important document requiring PSS signature"
    print(f"\nDocument: {message}")
    
    # Create PSS signature
    signature = rsa.sign_pss(message)
    print(f"\nPSS Signature: {signature[:50]}...")
    
    # Verify
    is_valid = rsa.verify_pss(message, signature)
    print(f"✓ Signature valid: {is_valid}")
    
    # Tamper test
    tampered = message + " (modified)"
    is_valid_tampered = rsa.verify_pss(tampered, signature)
    print(f"✗ Tampered document valid: {is_valid_tampered}")
    
    print("\nPSS vs PKCS#1 v1.5:")
    print("  - PSS: Provably secure, randomized")
    print("  - PKCS#1 v1.5: Older standard, deterministic")
    print("  - Recommendation: Use PSS for new applications")


def demonstrate_file_signing():
    """Demonstrate file signing and verification"""
    
    print("\n" + "=" * 70)
    print("File Signing and Verification")
    print("=" * 70)
    
    # Create test file
    test_file = "document.txt"
    signature_file = "document.sig"
    
    with open(test_file, 'w') as f:
        f.write("This is an important document.\n")
        f.write("It must be signed to verify authenticity.\n")
        f.write("Created for IDATT2503 at NTNU Trondheim.\n")
    
    # Generate keys
    rsa = RSAManager(2048)
    rsa.export_keys()
    
    # Sign file
    print(f"\n1. Signing {test_file}")
    with open(test_file, 'rb') as f:
        content = f.read()
    
    signature = rsa.sign(content)
    
    with open(signature_file, 'w') as f:
        f.write(signature)
    
    print(f"   ✓ Signature saved to {signature_file}")
    
    # Verify file
    print(f"\n2. Verifying {test_file}")
    
    with open(test_file, 'rb') as f:
        content = f.read()
    
    with open(signature_file, 'r') as f:
        signature = f.read()
    
    is_valid = rsa.verify(content, signature)
    print(f"   ✓ Signature valid: {is_valid}")
    
    # Tamper with file
    print(f"\n3. Tampering with {test_file}")
    with open(test_file, 'a') as f:
        f.write("Unauthorized addition!\n")
    
    # Try to verify tampered file
    with open(test_file, 'rb') as f:
        tampered_content = f.read()
    
    is_valid_tampered = rsa.verify(tampered_content, signature)
    print(f"   ✗ Tampered file valid: {is_valid_tampered}")
    
    # Cleanup
    os.remove(test_file)
    os.remove(signature_file)
    os.remove("private_key.pem")
    os.remove("public_key.pem")
    print("\n✓ Cleaned up temporary files")


def demonstrate_best_practices():
    """Demonstrate RSA best practices"""
    
    print("\n" + "=" * 70)
    print("RSA Best Practices")
    print("=" * 70)
    
    print("\n✓ DO:")
    print("  - Use at least 2048-bit keys (3072+ recommended)")
    print("  - Use OAEP padding for encryption")
    print("  - Use PSS for signatures (more secure than PKCS#1 v1.5)")
    print("  - Protect private keys with strong passwords")
    print("  - Use hybrid encryption for large messages")
    print("  - Verify all received signatures")
    print("  - Rotate keys periodically")
    
    print("\n✗ DON'T:")
    print("  - Don't use keys smaller than 2048 bits")
    print("  - Don't use RSA without padding (textbook RSA is insecure)")
    print("  - Don't encrypt large amounts of data with RSA directly")
    print("  - Don't share private keys")
    print("  - Don't reuse the same key for encryption and signing")
    print("  - Don't ignore certificate validation")
    
    print("\n💡 TIP: Use hybrid encryption (RSA + AES) for large data:")
    print("   1. Generate random AES key")
    print("   2. Encrypt data with AES")
    print("   3. Encrypt AES key with RSA")
    print("   4. Send both encrypted AES key and encrypted data")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_encryption()
    demonstrate_digital_signatures()
    demonstrate_key_exchange()
    demonstrate_key_sizes()
    demonstrate_pss_signatures()
    demonstrate_file_signing()
    demonstrate_best_practices()
    
    print("\n" + "=" * 70)
    print("All RSA Demonstrations Complete!")
    print("=" * 70)
