"""
Advanced AES Encryption Example for IDATT2503
Demonstrates different modes of operation and best practices
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

class AESCipher:
    """AES encryption wrapper with multiple modes"""
    
    def __init__(self, key=None):
        """Initialize with a key or generate a new one"""
        if key is None:
            self.key = get_random_bytes(32)  # 256-bit key
        else:
            self.key = key
    
    def encrypt_gcm(self, plaintext):
        """
        Encrypt using GCM mode (Galois/Counter Mode)
        - Provides both encryption and authentication
        - Recommended for most use cases
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Return nonce + tag + ciphertext
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    
    def decrypt_gcm(self, encrypted):
        """Decrypt GCM encrypted data"""
        encrypted = base64.b64decode(encrypted)
        
        # Extract components
        nonce = encrypted[:16]
        tag = encrypted[16:32]
        ciphertext = encrypted[32:]
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    
    def encrypt_cbc(self, plaintext):
        """
        Encrypt using CBC mode (Cipher Block Chaining)
        - Requires padding
        - Requires unpredictable IV
        - Less recommended than GCM
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # Generate random IV
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad to block size (128 bits = 16 bytes)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        
        # Return IV + ciphertext
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt_cbc(self, encrypted):
        """Decrypt CBC encrypted data"""
        encrypted = base64.b64decode(encrypted)
        
        # Extract IV and ciphertext
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    def encrypt_ctr(self, plaintext):
        """
        Encrypt using CTR mode (Counter Mode)
        - Converts block cipher into stream cipher
        - Parallelizable
        - Must never reuse nonce with same key
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        cipher = AES.new(self.key, AES.MODE_CTR)
        ciphertext = cipher.encrypt(plaintext)
        
        # Return nonce + ciphertext
        return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')
    
    def decrypt_ctr(self, encrypted):
        """Decrypt CTR encrypted data"""
        encrypted = base64.b64decode(encrypted)
        
        # Extract nonce and ciphertext
        nonce = encrypted[:8]  # CTR nonce is 8 bytes by default
        ciphertext = encrypted[8:]
        
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext.decode('utf-8')
    
    def save_key(self, filename):
        """Save key to file"""
        with open(filename, 'wb') as f:
            f.write(self.key)
    
    @staticmethod
    def load_key(filename):
        """Load key from file"""
        with open(filename, 'rb') as f:
            key = f.read()
        return AESCipher(key)


def demonstrate_modes():
    """Demonstrate different AES modes"""
    
    print("=" * 60)
    print("AES Encryption Modes Demonstration")
    print("=" * 60)
    
    message = "Hello from IDATT2503! This is a secure message."
    
    # Initialize cipher
    cipher = AESCipher()
    
    # GCM Mode (Recommended)
    print("\n1. GCM Mode (Galois/Counter Mode)")
    print("-" * 60)
    encrypted_gcm = cipher.encrypt_gcm(message)
    print(f"Encrypted: {encrypted_gcm[:50]}...")
    decrypted_gcm = cipher.decrypt_gcm(encrypted_gcm)
    print(f"Decrypted: {decrypted_gcm}")
    print(f"Match: {message == decrypted_gcm}")
    
    # CBC Mode
    print("\n2. CBC Mode (Cipher Block Chaining)")
    print("-" * 60)
    encrypted_cbc = cipher.encrypt_cbc(message)
    print(f"Encrypted: {encrypted_cbc[:50]}...")
    decrypted_cbc = cipher.decrypt_cbc(encrypted_cbc)
    print(f"Decrypted: {decrypted_cbc}")
    print(f"Match: {message == decrypted_cbc}")
    
    # CTR Mode
    print("\n3. CTR Mode (Counter Mode)")
    print("-" * 60)
    encrypted_ctr = cipher.encrypt_ctr(message)
    print(f"Encrypted: {encrypted_ctr[:50]}...")
    decrypted_ctr = cipher.decrypt_ctr(encrypted_ctr)
    print(f"Decrypted: {decrypted_ctr}")
    print(f"Match: {message == decrypted_ctr}")


def demonstrate_file_encryption():
    """Demonstrate file encryption"""
    
    print("\n" + "=" * 60)
    print("File Encryption Demonstration")
    print("=" * 60)
    
    # Create test file
    test_file = "test_plaintext.txt"
    encrypted_file = "test_encrypted.bin"
    decrypted_file = "test_decrypted.txt"
    
    with open(test_file, 'w') as f:
        f.write("This is sensitive information from NTNU!\n")
        f.write("It should be encrypted before storage.\n")
        f.write("Security is important in IDATT2503!\n")
    
    # Initialize cipher and save key
    cipher = AESCipher()
    cipher.save_key("secret.key")
    print("\n✓ Generated and saved encryption key")
    
    # Encrypt file
    with open(test_file, 'r') as f:
        content = f.read()
    
    encrypted = cipher.encrypt_gcm(content)
    
    with open(encrypted_file, 'w') as f:
        f.write(encrypted)
    
    print(f"✓ Encrypted {test_file} -> {encrypted_file}")
    
    # Decrypt file
    cipher2 = AESCipher.load_key("secret.key")
    
    with open(encrypted_file, 'r') as f:
        encrypted_content = f.read()
    
    decrypted = cipher2.decrypt_gcm(encrypted_content)
    
    with open(decrypted_file, 'w') as f:
        f.write(decrypted)
    
    print(f"✓ Decrypted {encrypted_file} -> {decrypted_file}")
    
    # Verify
    with open(decrypted_file, 'r') as f:
        decrypted_content = f.read()
    
    if content == decrypted_content:
        print("\n✓ Success! Original and decrypted files match")
    else:
        print("\n✗ Error: Files don't match")
    
    # Cleanup
    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)
    os.remove("secret.key")
    print("\n✓ Cleaned up temporary files")


def demonstrate_key_sizes():
    """Demonstrate different AES key sizes"""
    
    print("\n" + "=" * 60)
    print("AES Key Sizes")
    print("=" * 60)
    
    message = "Testing different key sizes"
    
    key_sizes = {
        "AES-128": 16,  # 128 bits
        "AES-192": 24,  # 192 bits
        "AES-256": 32   # 256 bits (recommended)
    }
    
    for name, size in key_sizes.items():
        key = get_random_bytes(size)
        cipher = AESCipher(key)
        encrypted = cipher.encrypt_gcm(message)
        decrypted = cipher.decrypt_gcm(encrypted)
        
        print(f"\n{name}:")
        print(f"  Key size: {size} bytes ({size * 8} bits)")
        print(f"  Encrypted: {encrypted[:40]}...")
        print(f"  Success: {message == decrypted}")


def demonstrate_security_best_practices():
    """Demonstrate security best practices"""
    
    print("\n" + "=" * 60)
    print("Security Best Practices")
    print("=" * 60)
    
    print("\n✓ DO:")
    print("  - Use AES-GCM for authenticated encryption")
    print("  - Generate new random nonce/IV for each encryption")
    print("  - Use 256-bit keys (AES-256)")
    print("  - Store keys securely (not in code!)")
    print("  - Use cryptographically secure random number generators")
    print("  - Protect keys with proper access controls")
    
    print("\n✗ DON'T:")
    print("  - Don't use ECB mode (reveals patterns)")
    print("  - Don't reuse nonces/IVs with the same key")
    print("  - Don't hardcode keys in source code")
    print("  - Don't use weak random number generators")
    print("  - Don't implement your own crypto primitives")
    print("  - Don't use CBC without authentication (use GCM instead)")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_modes()
    demonstrate_file_encryption()
    demonstrate_key_sizes()
    demonstrate_security_best_practices()
    
    print("\n" + "=" * 60)
    print("Demonstrations Complete!")
    print("=" * 60)
