"""
Secure File Encryption with AES-256-GCM

Complete example of encrypting/decrypting files securely using:
- AES-256-GCM (authenticated encryption)
- PBKDF2 key derivation (from password)
- Proper salt and nonce handling

PRODUCTION-READY EXAMPLE

Usage:
    python secure_file_encryption.py encrypt input.txt output.enc
    python secure_file_encryption.py decrypt output.enc decrypted.txt
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import sys
import getpass
from pathlib import Path


class SecureFileEncryption:
    """Secure file encryption using AES-256-GCM."""
    
    # Constants
    SALT_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    KEY_SIZE = 32  # 256 bits
    ITERATIONS = 600_000  # OWASP recommendation (2023)
    
    def __init__(self):
        pass
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt (must be unique per encryption)
            
        Returns:
            256-bit derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_file(self, input_path: str, output_path: str, password: str):
        """
        Encrypt a file with password.
        
        File format:
            [salt (16 bytes)][nonce (12 bytes)][ciphertext + tag]
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output
            password: Encryption password
        """
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random salt and nonce
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Derive key from password
        key = self.derive_key(password, salt)
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        
        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext_with_tag)
        
        print(f"✓ File encrypted successfully")
        print(f"  Input:  {input_path} ({len(plaintext)} bytes)")
        print(f"  Output: {output_path} ({len(salt) + len(nonce) + len(ciphertext_with_tag)} bytes)")
        print(f"  Key derivation: PBKDF2-SHA256 ({self.ITERATIONS:,} iterations)")
    
    def decrypt_file(self, input_path: str, output_path: str, password: str):
        """
        Decrypt a file with password.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            password: Decryption password
            
        Raises:
            ValueError: If authentication fails (wrong password or tampered file)
        """
        # Read encrypted file
        with open(input_path, 'rb') as f:
            salt = f.read(self.SALT_SIZE)
            nonce = f.read(self.NONCE_SIZE)
            ciphertext_with_tag = f.read()
        
        if len(salt) != self.SALT_SIZE or len(nonce) != self.NONCE_SIZE:
            raise ValueError("Invalid file format")
        
        # Derive key from password
        key = self.derive_key(password, salt)
        
        # Decrypt and verify with AES-256-GCM
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            raise ValueError("Decryption failed: wrong password or tampered file") from e
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"✓ File decrypted successfully")
        print(f"  Input:  {input_path}")
        print(f"  Output: {output_path} ({len(plaintext)} bytes)")
    
    def encrypt_file_with_key(self, input_path: str, output_path: str, key: bytes):
        """
        Encrypt file with pre-generated key (no password).
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output
            key: 256-bit encryption key
        """
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        
        # Write encrypted file (no salt needed)
        with open(output_path, 'wb') as f:
            f.write(nonce)
            f.write(ciphertext_with_tag)
        
        print(f"✓ File encrypted with key")
        print(f"  Output: {output_path}")
    
    def decrypt_file_with_key(self, input_path: str, output_path: str, key: bytes):
        """
        Decrypt file with pre-generated key (no password).
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            key: 256-bit encryption key
        """
        # Read encrypted file
        with open(input_path, 'rb') as f:
            nonce = f.read(self.NONCE_SIZE)
            ciphertext_with_tag = f.read()
        
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("Invalid file format")
        
        # Decrypt and verify
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"✓ File decrypted with key")
        print(f"  Output: {output_path}")


def demonstrate_file_encryption():
    """Demonstrate secure file encryption."""
    print("=" * 70)
    print("SECURE FILE ENCRYPTION DEMONSTRATION")
    print("=" * 70)
    
    encryptor = SecureFileEncryption()
    
    # Create test file
    test_file = "test_plaintext.txt"
    encrypted_file = "test_encrypted.bin"
    decrypted_file = "test_decrypted.txt"
    
    # Example 1: Password-based encryption
    print("\n[Example 1] Password-Based Encryption")
    print("-" * 70)
    
    # Create test content
    test_content = b"""This is a secret document.
It contains sensitive information that must be protected.
Only authorized users with the correct password should be able to read it.

This encryption uses:
- AES-256-GCM (authenticated encryption)
- PBKDF2-SHA256 (600,000 iterations)
- Random salt and nonce

CONFIDENTIAL - DO NOT SHARE
"""
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"Created test file: {test_file}")
    print(f"Content length: {len(test_content)} bytes\n")
    
    # Encrypt
    password = "MySecurePassword123!"
    print(f"Encrypting with password: {password}")
    encryptor.encrypt_file(test_file, encrypted_file, password)
    
    print(f"\nEncrypted file structure:")
    with open(encrypted_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()
    
    print(f"  Salt (16 bytes):      {salt.hex()}")
    print(f"  Nonce (12 bytes):     {nonce.hex()}")
    print(f"  Ciphertext + Tag:     {len(ciphertext)} bytes")
    
    # Decrypt with correct password
    print(f"\nDecrypting with correct password...")
    encryptor.decrypt_file(encrypted_file, decrypted_file, password)
    
    # Verify
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    print(f"\n✓ Decryption successful: {test_content == decrypted_content}")
    
    # Try wrong password
    print("\n[Example 2] Wrong Password Detection")
    print("-" * 70)
    
    wrong_password = "WrongPassword"
    print(f"Attempting to decrypt with wrong password: {wrong_password}")
    
    try:
        encryptor.decrypt_file(encrypted_file, "should_not_exist.txt", wrong_password)
        print("❌ ERROR: Should have failed!")
    except ValueError as e:
        print(f"✓ Decryption failed (as expected)")
        print(f"  Error: {e}")
    
    # Example 3: Key-based encryption (no password)
    print("\n[Example 3] Key-Based Encryption (No Password)")
    print("-" * 70)
    
    # Generate random key
    key = AESGCM.generate_key(bit_length=256)
    print(f"Generated 256-bit key: {key.hex()}")
    
    key_encrypted = "test_key_encrypted.bin"
    key_decrypted = "test_key_decrypted.txt"
    
    encryptor.encrypt_file_with_key(test_file, key_encrypted, key)
    encryptor.decrypt_file_with_key(key_encrypted, key_decrypted, key)
    
    with open(key_decrypted, 'rb') as f:
        key_decrypted_content = f.read()
    
    print(f"✓ Key-based encryption successful: {test_content == key_decrypted_content}")
    
    # Example 4: Tamper detection
    print("\n[Example 4] Tamper Detection")
    print("-" * 70)
    
    # Read encrypted file
    with open(encrypted_file, 'rb') as f:
        original_data = f.read()
    
    # Tamper with one byte
    tampered_data = bytearray(original_data)
    tampered_data[-10] ^= 1  # Flip one bit in ciphertext
    
    tampered_file = "test_tampered.bin"
    with open(tampered_file, 'wb') as f:
        f.write(bytes(tampered_data))
    
    print(f"Modified one byte in encrypted file")
    print(f"Attempting to decrypt tampered file...")
    
    try:
        encryptor.decrypt_file(tampered_file, "should_not_exist.txt", password)
        print("❌ ERROR: Should have detected tampering!")
    except ValueError as e:
        print(f"✓ Tampering detected (as expected)")
        print(f"  Error: {e}")
    
    # Cleanup
    import os as os_module
    for file in [test_file, encrypted_file, decrypted_file, key_encrypted, 
                 key_decrypted, tampered_file]:
        try:
            os_module.remove(file)
        except:
            pass
    
    print("\n" + "=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)


def main():
    """Command-line interface."""
    if len(sys.argv) < 4:
        print("Usage:")
        print("  Encrypt: python secure_file_encryption.py encrypt <input> <output>")
        print("  Decrypt: python secure_file_encryption.py decrypt <input> <output>")
        print("\nExample:")
        print("  python secure_file_encryption.py encrypt secret.txt secret.enc")
        print("  python secure_file_encryption.py decrypt secret.enc decrypted.txt")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Validate input file exists
    if not Path(input_file).exists():
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    encryptor = SecureFileEncryption()
    
    # Get password securely
    password = getpass.getpass("Enter password: ")
    
    if command == 'encrypt':
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords don't match")
            sys.exit(1)
        
        encryptor.encrypt_file(input_file, output_file, password)
        
    elif command == 'decrypt':
        try:
            encryptor.decrypt_file(input_file, output_file, password)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    else:
        print(f"Error: Unknown command '{command}'")
        print("Use 'encrypt' or 'decrypt'")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command-line mode
        main()
    else:
        # Demonstration mode
        demonstrate_file_encryption()
