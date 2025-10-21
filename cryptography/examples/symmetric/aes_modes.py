"""
AES Modes of Operation - Educational Examples

Demonstrates different modes of AES encryption:
- ECB (Electronic Codebook) - INSECURE
- CBC (Cipher Block Chaining)
- CTR (Counter Mode)
- GCM (Galois/Counter Mode) - RECOMMENDED

EDUCATIONAL PURPOSE ONLY
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to data.
    
    Args:
        data: Data to pad
        block_size: Block size in bytes (default 16 for AES)
        
    Returns:
        Padded data
    """
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data
        block_size: Block size in bytes (default 16 for AES)
        
    Returns:
        Unpadded data
    """
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# ============================================================================
# ECB MODE - INSECURE, FOR EDUCATIONAL PURPOSES ONLY!
# ============================================================================

def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt using AES-ECB mode.
    
    ⚠️ WARNING: ECB is INSECURE! Identical blocks produce identical ciphertext.
    This function is for educational purposes only.
    
    Args:
        plaintext: Data to encrypt
        key: 128, 192, or 256-bit key
        
    Returns:
        Ciphertext
    """
    # Pad plaintext to block size
    padded = pad_pkcs7(plaintext)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return ciphertext


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt using AES-ECB mode.
    
    Args:
        ciphertext: Data to decrypt
        key: Same key used for encryption
        
    Returns:
        Plaintext
    """
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Decrypt
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = unpad_pkcs7(padded)
    
    return plaintext


def demonstrate_ecb_weakness():
    """Demonstrate why ECB mode is insecure."""
    print("=" * 70)
    print("ECB MODE WEAKNESS DEMONSTRATION")
    print("=" * 70)
    
    key = os.urandom(32)  # 256-bit key
    
    # Example 1: Same blocks produce same ciphertext
    print("\n[Example 1] Identical Blocks Problem")
    print("-" * 70)
    
    plaintext = b"HELLO WORLD!!!!!" * 3  # Repeated block
    ciphertext = encrypt_ecb(plaintext, key)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Show blocks
    block_size = 16
    print("\nCiphertext blocks (16 bytes each):")
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        print(f"  Block {i//block_size + 1}: {block.hex()}")
    
    print("\n⚠️ Notice: Identical plaintext blocks → identical ciphertext blocks!")
    print("   An attacker can see patterns even without decrypting!")
    
    # Example 2: Pattern detection
    print("\n[Example 2] Pattern Detection")
    print("-" * 70)
    
    # Simulate repeating data (like image with uniform color)
    repeated_data = b"AAAA" * 4  # 16 bytes
    varied_data = b"ABCDEFGHIJKLMNOP"  # 16 bytes, all different
    
    message = repeated_data + varied_data + repeated_data
    ciphertext = encrypt_ecb(message, key)
    
    print("Message structure:")
    print("  Block 1: AAAA repeated (16 bytes)")
    print("  Block 2: ABCD... varied (16 bytes)")
    print("  Block 3: AAAA repeated (16 bytes) - SAME AS BLOCK 1")
    
    print("\nCiphertext blocks:")
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        print(f"  Block {i//block_size + 1}: {block.hex()}")
    
    print("\n⚠️ Block 1 and Block 3 have IDENTICAL ciphertext!")
    print("   This leaks information about plaintext structure.")
    
    # Example 3: Block reordering attack
    print("\n[Example 3] Block Reordering Attack")
    print("-" * 70)
    
    message = b"TRANSFER $100.00" + b"TO: ALICE       "
    ciphertext = encrypt_ecb(message, key)
    
    print(f"Original message: {message}")
    print(f"Original blocks:")
    print(f"  Block 1: {message[:16]}")
    print(f"  Block 2: {message[16:32]}")
    
    # Attacker reorders blocks
    block1 = ciphertext[:16]
    block2 = ciphertext[16:32]
    modified_ciphertext = block2 + block1  # Swap blocks!
    
    decrypted = decrypt_ecb(modified_ciphertext, key)
    print(f"\nModified (swapped blocks): {decrypted}")
    
    print("\n⚠️ Attacker reordered blocks without knowing the key!")
    print("   ECB mode doesn't protect against tampering.")
    
    print("\n" + "=" * 70)
    print("CONCLUSION: NEVER USE ECB MODE!")
    print("=" * 70)


# ============================================================================
# CBC MODE - Cipher Block Chaining
# ============================================================================

def encrypt_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt using AES-CBC mode.
    
    Args:
        plaintext: Data to encrypt
        key: 128, 192, or 256-bit key
        
    Returns:
        Tuple of (IV, ciphertext)
    """
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext
    padded = pad_pkcs7(plaintext)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return iv, ciphertext


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt using AES-CBC mode.
    
    Args:
        ciphertext: Data to decrypt
        key: Same key used for encryption
        iv: Same IV used for encryption
        
    Returns:
        Plaintext
    """
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Decrypt
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = unpad_pkcs7(padded)
    
    return plaintext


def demonstrate_cbc():
    """Demonstrate CBC mode."""
    print("\n" + "=" * 70)
    print("CBC MODE DEMONSTRATION")
    print("=" * 70)
    
    key = os.urandom(32)
    
    # Example 1: Basic encryption
    print("\n[Example 1] Basic CBC Encryption")
    print("-" * 70)
    
    plaintext = b"Hello, this is a secret message!"
    iv, ciphertext = encrypt_cbc(plaintext, key)
    decrypted = decrypt_cbc(ciphertext, key, iv)
    
    print(f"Plaintext:  {plaintext}")
    print(f"IV (hex):   {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: Same plaintext, different IV
    print("\n[Example 2] IV Randomization")
    print("-" * 70)
    
    plaintext = b"Same message encrypted twice"
    
    iv1, ciphertext1 = encrypt_cbc(plaintext, key)
    iv2, ciphertext2 = encrypt_cbc(plaintext, key)
    
    print(f"Plaintext:     {plaintext}")
    print(f"\nEncryption 1:")
    print(f"  IV:          {iv1.hex()}")
    print(f"  Ciphertext:  {ciphertext1.hex()[:40]}...")
    print(f"\nEncryption 2:")
    print(f"  IV:          {iv2.hex()}")
    print(f"  Ciphertext:  {ciphertext2.hex()[:40]}...")
    
    print(f"\n✓ Different IVs → Different ciphertexts")
    print(f"  (Even for same plaintext and key)")
    
    # Example 3: Identical blocks with CBC
    print("\n[Example 3] CBC Hides Patterns")
    print("-" * 70)
    
    repeated_message = b"HELLO WORLD!!!!!" * 3
    iv, ciphertext = encrypt_cbc(repeated_message, key)
    
    print(f"Plaintext: {repeated_message}")
    print(f"\nCiphertext blocks:")
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        print(f"  Block {i//16 + 1}: {block.hex()}")
    
    print(f"\n✓ All blocks are different (even though plaintext repeats)")
    print(f"  CBC successfully hides patterns!")


# ============================================================================
# CTR MODE - Counter Mode
# ============================================================================

def encrypt_ctr(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt using AES-CTR mode.
    
    Args:
        plaintext: Data to encrypt
        key: 128, 192, or 256-bit key
        
    Returns:
        Tuple of (nonce, ciphertext)
    """
    # Generate random nonce
    nonce = os.urandom(16)
    
    # Create cipher (no padding needed for CTR!)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return nonce, ciphertext


def decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt using AES-CTR mode.
    
    Args:
        ciphertext: Data to decrypt
        key: Same key used for encryption
        nonce: Same nonce used for encryption
        
    Returns:
        Plaintext
    """
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    
    # Decrypt (same operation as encryption!)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


def demonstrate_ctr():
    """Demonstrate CTR mode."""
    print("\n" + "=" * 70)
    print("CTR MODE DEMONSTRATION")
    print("=" * 70)
    
    key = os.urandom(32)
    
    # Example 1: Basic encryption
    print("\n[Example 1] Basic CTR Encryption")
    print("-" * 70)
    
    plaintext = b"Counter mode is like a stream cipher!"
    nonce, ciphertext = encrypt_ctr(plaintext, key)
    decrypted = decrypt_ctr(ciphertext, key, nonce)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Nonce:      {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: No padding needed
    print("\n[Example 2] No Padding Required")
    print("-" * 70)
    
    # Odd-length messages work fine
    messages = [
        b"Short",
        b"Medium length message",
        b"A very long message that is definitely not a multiple of 16 bytes!"
    ]
    
    for msg in messages:
        nonce, ciphertext = encrypt_ctr(msg, key)
        print(f"Plaintext length:  {len(msg)} bytes")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"✓ Same length (no padding)\n")
    
    # Example 3: Nonce reuse catastrophe!
    print("[Example 3] Nonce Reuse Attack")
    print("-" * 70)
    
    # Same nonce, different messages
    nonce = os.urandom(16)
    
    msg1 = b"First secret message"
    msg2 = b"Second secret msg!!!"
    
    cipher1 = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    cipher2 = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    
    ciphertext1 = cipher1.encryptor().update(msg1) + cipher1.encryptor().finalize()
    ciphertext2 = cipher2.encryptor().update(msg2) + cipher2.encryptor().finalize()
    
    print(f"Message 1: {msg1}")
    print(f"Message 2: {msg2}")
    print(f"\nCiphertext 1: {ciphertext1.hex()}")
    print(f"Ciphertext 2: {ciphertext2.hex()}")
    
    # XOR ciphertexts reveals XOR of plaintexts!
    xor_result = bytes(a ^ b for a, b in zip(ciphertext1, ciphertext2))
    expected = bytes(a ^ b for a, b in zip(msg1, msg2))
    
    print(f"\nC1 ⊕ C2 = {xor_result.hex()}")
    print(f"M1 ⊕ M2 = {expected.hex()}")
    print(f"\n⚠️ CATASTROPHIC: Nonce reuse leaks plaintext XOR!")
    print(f"   C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K) = M1 ⊕ M2")
    print(f"   Attacker can recover plaintexts!")


# ============================================================================
# GCM MODE - RECOMMENDED for real applications
# ============================================================================

def encrypt_gcm(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """
    Encrypt using AES-GCM mode (authenticated encryption).
    
    Args:
        plaintext: Data to encrypt
        key: 128, 192, or 256-bit key
        associated_data: Data to authenticate but not encrypt
        
    Returns:
        Tuple of (nonce, ciphertext_with_tag, associated_data)
    """
    # Create GCM cipher
    aesgcm = AESGCM(key)
    
    # Generate random nonce
    nonce = os.urandom(12)  # 96 bits recommended for GCM
    
    # Encrypt and authenticate
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    return nonce, ciphertext_with_tag, associated_data


def decrypt_gcm(nonce: bytes, ciphertext_with_tag: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt using AES-GCM mode (with authentication verification).
    
    Args:
        nonce: Same nonce used for encryption
        ciphertext_with_tag: Ciphertext with authentication tag
        key: Same key used for encryption
        associated_data: Same AAD used for encryption
        
    Returns:
        Plaintext (raises exception if authentication fails)
    """
    # Create GCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt and verify
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    
    return plaintext


def demonstrate_gcm():
    """Demonstrate GCM mode - recommended for production."""
    print("\n" + "=" * 70)
    print("GCM MODE DEMONSTRATION (RECOMMENDED)")
    print("=" * 70)
    
    key = AESGCM.generate_key(bit_length=256)
    
    # Example 1: Basic authenticated encryption
    print("\n[Example 1] Authenticated Encryption")
    print("-" * 70)
    
    plaintext = b"Sensitive data that must not be tampered with!"
    nonce, ciphertext_with_tag, _ = encrypt_gcm(plaintext, key)
    decrypted = decrypt_gcm(nonce, ciphertext_with_tag, key)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Nonce:      {nonce.hex()}")
    print(f"Ciphertext + Tag: {ciphertext_with_tag.hex()}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: Additional Authenticated Data (AAD)
    print("\n[Example 2] Additional Authenticated Data (AAD)")
    print("-" * 70)
    
    plaintext = b"Encrypted payload"
    aad = b"Authenticated header (not encrypted)"
    
    nonce, ciphertext_with_tag, _ = encrypt_gcm(plaintext, key, aad)
    decrypted = decrypt_gcm(nonce, ciphertext_with_tag, key, aad)
    
    print(f"Plaintext:  {plaintext}")
    print(f"AAD:        {aad}")
    print(f"Ciphertext: {ciphertext_with_tag.hex()}")
    print(f"Decrypted:  {decrypted}")
    print(f"\n✓ AAD is authenticated but not encrypted")
    print(f"  (Useful for headers, metadata, etc.)")
    
    # Example 3: Tamper detection
    print("\n[Example 3] Tamper Detection")
    print("-" * 70)
    
    plaintext = b"Original message"
    nonce, ciphertext_with_tag, _ = encrypt_gcm(plaintext, key)
    
    # Attacker modifies ciphertext
    modified = bytearray(ciphertext_with_tag)
    modified[0] ^= 1  # Flip one bit
    modified = bytes(modified)
    
    print(f"Original ciphertext: {ciphertext_with_tag.hex()}")
    print(f"Modified ciphertext: {modified.hex()}")
    
    try:
        decrypted = decrypt_gcm(nonce, modified, key)
        print("❌ ERROR: Should have failed authentication!")
    except Exception as e:
        print(f"\n✓ Authentication failed (as expected)")
        print(f"  Exception: {type(e).__name__}")
        print(f"  GCM detected tampering!")
    
    # Example 4: Wrong AAD detection
    print("\n[Example 4] Wrong AAD Detection")
    print("-" * 70)
    
    plaintext = b"Message"
    aad1 = b"Correct header"
    aad2 = b"Wrong header!!"
    
    nonce, ciphertext_with_tag, _ = encrypt_gcm(plaintext, key, aad1)
    
    print(f"Encrypted with AAD: {aad1}")
    print(f"Trying to decrypt with AAD: {aad2}")
    
    try:
        decrypted = decrypt_gcm(nonce, ciphertext_with_tag, key, aad2)
        print("❌ ERROR: Should have failed!")
    except Exception:
        print(f"\n✓ Authentication failed")
        print(f"  GCM detects wrong AAD!")


def compare_modes():
    """Compare all modes side by side."""
    print("\n" + "=" * 70)
    print("MODE COMPARISON SUMMARY")
    print("=" * 70)
    
    print("\n| Feature         | ECB    | CBC    | CTR    | GCM    |")
    print("|-----------------|--------|--------|--------|--------|")
    print("| Security        | ❌ Bad | ⚠️ OK  | ✅ Good| ✅ Best|")
    print("| Patterns hidden | ❌ No  | ✅ Yes | ✅ Yes | ✅ Yes |")
    print("| Parallel        | ✅ Yes | ⚠️ Dec | ✅ Yes | ✅ Yes |")
    print("| Authentication  | ❌ No  | ❌ No  | ❌ No  | ✅ Yes |")
    print("| Padding needed  | ✅ Yes | ✅ Yes | ❌ No  | ❌ No  |")
    print("| IV/Nonce        | None   | Random | Random | Random |")
    print("| Use in practice | ❌ NEVER|⚠️ Rare | ⚠️ Rare| ✅ YES!|")
    
    print("\n" + "=" * 70)
    print("RECOMMENDATION: Use AES-256-GCM for all new applications!")
    print("=" * 70)


if __name__ == "__main__":
    # Run all demonstrations
    demonstrate_ecb_weakness()
    demonstrate_cbc()
    demonstrate_ctr()
    demonstrate_gcm()
    compare_modes()
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
Key Takeaways:

1. ECB Mode:
   - ❌ NEVER USE IN PRACTICE
   - Identical blocks → identical ciphertext
   - Patterns are visible to attacker
   - Vulnerable to block reordering

2. CBC Mode:
   - ⚠️ OK, but prefer GCM
   - Requires random IV
   - Needs padding
   - No authentication (use with HMAC)

3. CTR Mode:
   - ✅ Good performance
   - No padding needed
   - Parallelizable
   - ⚠️ MUST NEVER reuse nonce
   - No authentication

4. GCM Mode:
   - ✅ RECOMMENDED FOR PRODUCTION
   - Authenticated encryption
   - Detects tampering
   - Fast (parallelizable)
   - Supports AAD

Best Practice:
→ Use AES-256-GCM for all new applications!
→ Never reuse nonce/IV with the same key
→ Always use authenticated encryption
→ Use established libraries (don't roll your own)
    """)
