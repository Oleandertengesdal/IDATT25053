#!/usr/bin/env python3
"""
AES-256-GCM Encryption Example

Demonstrates authenticated encryption using AES-GCM mode.
This is the recommended way to encrypt data.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


def encrypt_message(message: str, key: bytes = None) -> tuple:
    """
    Encrypt a message using AES-256-GCM.
    
    Args:
        message: String to encrypt
        key: 32-byte encryption key (generated if not provided)
    
    Returns:
        tuple: (encrypted_data, nonce, key)
    """
    # Generate key if not provided
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    
    # Create AESGCM instance
    aesgcm = AESGCM(key)
    
    # Generate random nonce (96 bits recommended for GCM)
    nonce = os.urandom(12)
    
    # Additional authenticated data (optional)
    aad = b"additional_data"
    
    # Encrypt
    message_bytes = message.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, message_bytes, aad)
    
    return ciphertext, nonce, key


def decrypt_message(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """
    Decrypt a message encrypted with AES-256-GCM.
    
    Args:
        ciphertext: Encrypted data
        nonce: Nonce used for encryption
        key: Encryption key
    
    Returns:
        str: Decrypted message
    """
    aesgcm = AESGCM(key)
    aad = b"additional_data"
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


def main():
    print("=== AES-256-GCM Encryption Example ===\n")
    
    # Original message
    message = "This is a secret message!"
    print(f"Original message: {message}")
    
    # Encrypt
    ciphertext, nonce, key = encrypt_message(message)
    
    print(f"\nKey (base64):        {base64.b64encode(key).decode()}")
    print(f"Nonce (base64):      {base64.b64encode(nonce).decode()}")
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
    
    # Decrypt
    decrypted = decrypt_message(ciphertext, nonce, key)
    print(f"\nDecrypted message: {decrypted}")
    
    # Verify
    assert message == decrypted, "Decryption failed!"
    print("\n✓ Encryption and decryption successful!")
    
    # Demonstrate authentication
    print("\n--- Testing Authentication ---")
    print("Attempting to decrypt with wrong key...")
    wrong_key = AESGCM.generate_key(bit_length=256)
    result = decrypt_message(ciphertext, nonce, wrong_key)
    if result is None:
        print("✓ Authentication works! Cannot decrypt with wrong key.")


if __name__ == "__main__":
    main()
