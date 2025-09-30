#!/usr/bin/env python3
"""
RSA Encryption and Digital Signatures Example

Demonstrates RSA public-key cryptography including:
- Key generation
- Encryption/Decryption
- Digital signatures
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_key_pair():
    """Generate RSA key pair (4096-bit for security)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_rsa(message: str, public_key) -> bytes:
    """Encrypt message using RSA public key."""
    message_bytes = message.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_rsa(ciphertext: bytes, private_key) -> str:
    """Decrypt message using RSA private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')


def sign_message(message: str, private_key) -> bytes:
    """Create digital signature for message."""
    message_bytes = message.encode('utf-8')
    
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message: str, signature: bytes, public_key) -> bool:
    """Verify digital signature."""
    message_bytes = message.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def main():
    print("=== RSA Encryption and Signatures Example ===\n")
    
    # Generate key pair
    print("Generating 4096-bit RSA key pair...")
    private_key, public_key = generate_key_pair()
    print("✓ Key pair generated\n")
    
    # === Encryption/Decryption ===
    print("--- Encryption/Decryption Demo ---")
    message = "Secret message for encryption"
    print(f"Original message: {message}")
    
    # Encrypt with public key
    ciphertext = encrypt_rsa(message, public_key)
    print(f"Encrypted (hex):  {ciphertext[:32].hex()}...")
    
    # Decrypt with private key
    decrypted = decrypt_rsa(ciphertext, private_key)
    print(f"Decrypted:        {decrypted}")
    
    assert message == decrypted
    print("✓ Encryption/Decryption successful!\n")
    
    # === Digital Signatures ===
    print("--- Digital Signature Demo ---")
    document = "This is an important document."
    print(f"Document: {document}")
    
    # Sign with private key
    signature = sign_message(document, private_key)
    print(f"Signature (hex): {signature[:32].hex()}...")
    
    # Verify with public key
    is_valid = verify_signature(document, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    # Test with tampered document
    print("\nTesting with tampered document...")
    tampered = "This is a tampered document."
    is_valid_tampered = verify_signature(tampered, signature, public_key)
    print(f"Tampered signature valid: {is_valid_tampered}")
    
    if is_valid and not is_valid_tampered:
        print("\n✓ Digital signature verification working correctly!")
    
    # === Key Serialization ===
    print("\n--- Key Serialization ---")
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(f"Private key (PEM):\n{private_pem.decode()[:100]}...")
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"\nPublic key (PEM):\n{public_pem.decode()[:100]}...")


if __name__ == "__main__":
    main()
