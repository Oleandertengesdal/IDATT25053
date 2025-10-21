# Crypto 2: Block Ciphers and Symmetric Encryption

**IDATT2503 Cryptography Learning Resource**  
**Topic:** Modern symmetric-key cryptography, block ciphers, and modes of operation

---

## Table of Contents

1. [Introduction to Symmetric Cryptography](#introduction)
2. [Block Cipher Fundamentals](#block-cipher-fundamentals)
3. [DES (Data Encryption Standard)](#des)
4. [AES (Advanced Encryption Standard)](#aes)
5. [Modes of Operation](#modes-of-operation)
6. [Padding Schemes](#padding-schemes)
7. [Security Considerations](#security-considerations)
8. [Authenticated Encryption](#authenticated-encryption)
9. [Practical Guidelines](#practical-guidelines)
10. [Comparison and Best Practices](#comparison-and-best-practices)

---

## Introduction to Symmetric Cryptography {#introduction}

### What is Symmetric Encryption?

**Symmetric encryption** uses the **same key** for both encryption and decryption.

```
Encryption: E(K, M) = C
Decryption: D(K, C) = M
```

Where:
- `K` = Secret key (same for encryption and decryption)
- `M` = Plaintext message
- `C` = Ciphertext

### Key Properties

1. **Fast:** Much faster than asymmetric encryption
2. **Efficient:** Suitable for large amounts of data
3. **Key Distribution Problem:** Both parties need same secret key
4. **Key Management:** Need secure way to share keys

### Symmetric vs Asymmetric

| Property | Symmetric | Asymmetric |
|----------|-----------|------------|
| Keys | Same key | Key pair (public/private) |
| Speed | Very fast (MB/s) | Slow (KB/s) |
| Key size | 128-256 bits | 2048-4096 bits |
| Use case | Bulk encryption | Key exchange, signatures |
| Example | AES | RSA, ECC |

### Types of Symmetric Ciphers

1. **Stream Ciphers:**
   - Encrypt one bit/byte at a time
   - Example: ChaCha20, RC4 (broken)
   - Use: Network protocols, disk encryption

2. **Block Ciphers:** (This module's focus)
   - Encrypt fixed-size blocks
   - Example: AES, DES
   - Use: Most encryption applications

---

## Block Cipher Fundamentals {#block-cipher-fundamentals}

### What is a Block Cipher?

A **block cipher** encrypts data in fixed-size blocks (e.g., 128 bits for AES).

```
Input:  64-bit or 128-bit block of plaintext
Key:    Secret key (56, 128, 192, or 256 bits)
Output: Same-size block of ciphertext
```

### Core Principles

#### 1. Confusion and Diffusion (Shannon, 1949)

**Confusion:** Makes relationship between key and ciphertext complex
- Small change in key → large change in ciphertext
- Implemented via **substitution** (S-boxes)

**Diffusion:** Spreads plaintext statistics throughout ciphertext
- Small change in plaintext → large change in ciphertext
- Implemented via **permutation** (P-boxes)

**Example:**
```
Plaintext:  01001010
Change 1 bit: 01001011
             ↓
Ciphertext:  10110101  (many bits changed)
```

#### 2. Substitution-Permutation Network (SPN)

Modern block ciphers use SPN structure:

```
Round 1:  Plaintext → [SubBytes] → [ShiftRows] → [MixColumns] → [AddRoundKey]
Round 2:  State → [SubBytes] → [ShiftRows] → [MixColumns] → [AddRoundKey]
...
Round N:  State → [SubBytes] → [ShiftRows] → [AddRoundKey] → Ciphertext
```

Each round:
1. **Substitution (S-box):** Replace bytes with values from lookup table
2. **Permutation:** Rearrange bits/bytes
3. **Key mixing:** XOR with round key
4. **Repeat:** Multiple rounds for security

#### 3. Feistel Network

Alternative structure (used in DES):

```
Left Half (L)    Right Half (R)
     |                |
     |                ↓
     |          [Round Function(R, K)]
     |                |
     +←──[XOR]←───────+
     |                |
    R'               L'
```

Properties:
- **Reversible:** Same structure for encryption/decryption
- **Half-block at a time:** Only R is modified per round
- Used in: DES, Blowfish, Twofish

---

## DES (Data Encryption Standard) {#des}

### History

- **1977:** Adopted as US federal standard
- **1999:** Broken in 22 hours (distributed computing)
- **2005:** COPACOBANA machine broke it in days
- **Today:** INSECURE - use only for educational purposes

### Specifications

- **Block size:** 64 bits (8 bytes)
- **Key size:** 56 bits (actually 64 bits with 8 parity bits)
- **Rounds:** 16
- **Structure:** Feistel network

### How DES Works

#### 1. Initial Permutation (IP)

Rearrange input bits according to fixed table:

```
Input:  Bits 1,2,3,...,64
Output: Bits 58,50,42,...,7
```

#### 2. Key Schedule

From 56-bit key, generate 16 round keys (48 bits each):

```
Key (56 bits) → [Permuted Choice 1] → [Split: C₀, D₀]
                                         ↓
                              [Rotate left] → C₁, D₁
                                         ↓
                        [Permuted Choice 2] → K₁ (48 bits)
```

#### 3. Feistel Rounds (16 times)

For each round `i`:

```
Lᵢ = Rᵢ₋₁
Rᵢ = Lᵢ₋₁ ⊕ f(Rᵢ₋₁, Kᵢ)
```

**Round function f:**
```
R (32 bits) → [Expansion] → E(R) (48 bits)
                              ↓
                    E(R) ⊕ Kᵢ (48 bits)
                              ↓
                    [S-boxes] → 32 bits
                              ↓
                    [Permutation] → f output (32 bits)
```

**S-boxes:** 8 boxes, each maps 6 bits → 4 bits

#### 4. Final Permutation (FP)

Inverse of initial permutation.

### DES Security

**Why DES is Insecure:**

1. **Small key space:** 2^56 ≈ 72 quadrillion keys
   - Modern computers: ~10^9 keys/second
   - Time to break: 2^56 / 10^9 / 86400 ≈ **834 days**
   - Distributed: **hours to days**

2. **Small block size:** 64 bits
   - Birthday attack after 2^32 blocks ≈ 32 GB
   - Must rekey frequently

3. **Known attacks:**
   - **Differential cryptanalysis:** 2^47 chosen plaintexts
   - **Linear cryptanalysis:** 2^43 known plaintexts

### Triple DES (3DES)

Workaround for DES weakness:

```
C = E_{K3}(D_{K2}(E_{K1}(P)))
```

- **Effective key size:** 168 bits (3 × 56)
- **Still secure** (though slow)
- **Deprecated:** Use AES instead

### DES Example (Conceptual)

```
Plaintext:  0123456789ABCDEF (hex)
Key:        133457799BBCDFF1 (hex)
↓
[Initial Permutation]
↓
[16 Feistel Rounds with round keys]
↓
[Final Permutation]
↓
Ciphertext: 85E813540F0AB405 (hex)
```

---

## AES (Advanced Encryption Standard) {#aes}

### History

- **1997:** NIST announces competition for DES replacement
- **2000:** Rijndael algorithm selected (by Daemen & Rijmen)
- **2001:** AES officially adopted
- **Today:** Global standard, used everywhere

### Specifications

| Parameter | Value |
|-----------|-------|
| **Block size** | 128 bits (16 bytes) |
| **Key sizes** | 128, 192, or 256 bits |
| **Rounds** | 10 (128-bit), 12 (192-bit), 14 (256-bit) |
| **Structure** | Substitution-Permutation Network (SPN) |

### Why AES is Better than DES

1. **Larger key:** 128/192/256 bits vs 56 bits
2. **Larger block:** 128 bits vs 64 bits
3. **Faster:** Optimized for modern CPUs
4. **More secure:** No practical attacks
5. **Flexible:** Multiple key sizes

### AES Structure

AES operates on a **4×4 array of bytes** called the **state**:

```
State (128 bits = 16 bytes):

    Column 0  1  2  3
Row 0   b₀  b₄  b₈  b₁₂
    1   b₁  b₅  b₉  b₁₃
    2   b₂  b₆  b₁₀ b₁₄
    3   b₃  b₇  b₁₁ b₁₅
```

### AES Round Operations

Each round applies 4 transformations:

#### 1. SubBytes (Substitution)

Replace each byte using S-box lookup table:

```
b → S-box[b]

Example:
Input byte:  0x53
S-box value: 0xED
```

**S-box properties:**
- Non-linear (provides confusion)
- Based on multiplicative inverse in GF(2^8)
- Designed to resist known attacks

#### 2. ShiftRows (Permutation)

Cyclically shift rows:

```
Row 0: No shift
Row 1: Shift left 1 byte
Row 2: Shift left 2 bytes
Row 3: Shift left 3 bytes

Before:         After:
b₀  b₄  b₈  b₁₂   b₀  b₄  b₈  b₁₂
b₁  b₅  b₉  b₁₃ → b₅  b₉  b₁₃ b₁
b₂  b₆  b₁₀ b₁₄   b₁₀ b₁₄ b₂  b₆
b₃  b₇  b₁₁ b₁₅   b₁₅ b₃  b₇  b₁₁
```

**Purpose:** Diffusion across columns

#### 3. MixColumns (Diffusion)

Matrix multiplication in GF(2^8):

```
Each column: [c₀, c₁, c₂, c₃] → [d₀, d₁, d₂, d₃]

[d₀]   [02 03 01 01]   [c₀]
[d₁] = [01 02 03 01] × [c₁]
[d₂]   [01 01 02 03]   [c₂]
[d₃]   [03 01 01 02]   [c₃]
```

**Purpose:** Mix data within each column (strong diffusion)

**Note:** Skipped in final round

#### 4. AddRoundKey (Key Mixing)

XOR state with round key:

```
State ⊕ RoundKey

Example:
State:     0x01 0x02 0x03 0x04
Round Key: 0x10 0x20 0x30 0x40
Result:    0x11 0x22 0x33 0x44
```

### AES Key Schedule

Generate round keys from original key:

```
AES-128: 10 rounds → 11 round keys (176 bytes total)
AES-192: 12 rounds → 13 round keys (208 bytes total)
AES-256: 14 rounds → 15 round keys (240 bytes total)
```

**Process:**
1. First round key = original key
2. Each subsequent key derived from previous using:
   - **RotWord:** Rotate bytes
   - **SubWord:** Apply S-box
   - **Rcon:** XOR with round constant
   - **XOR with previous key**

### AES Encryption Process

```
Input: Plaintext (128 bits), Key (128/192/256 bits)

1. AddRoundKey (with original key)

2. For rounds 1 to N-1:
     SubBytes
     ShiftRows
     MixColumns
     AddRoundKey

3. Final round:
     SubBytes
     ShiftRows
     AddRoundKey (no MixColumns!)

Output: Ciphertext (128 bits)
```

### AES Decryption

Inverse operations in reverse order:

- **InvSubBytes:** Use inverse S-box
- **InvShiftRows:** Shift right instead of left
- **InvMixColumns:** Use inverse matrix
- **AddRoundKey:** Same (XOR is self-inverse)

### AES Security

**Status:** No practical attacks on full AES

**Best known attacks:**
- **AES-128:** 2^126.1 operations (theoretical, impractical)
- **AES-192:** 2^189.7 operations
- **AES-256:** 2^254.4 operations (related-key attack)

**Related-key attacks:** Only matter if attacker controls key schedule (rare)

**Brute force:**
- **AES-128:** 2^128 ≈ 3.4 × 10^38 keys
- **AES-256:** 2^256 ≈ 1.2 × 10^77 keys (more atoms than in the universe!)

**Conclusion:** AES-128 is secure. AES-256 for maximum security.

### AES Example (High-Level)

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate random 256-bit key
key = os.urandom(32)  # 32 bytes = 256 bits

# Create AES cipher
cipher = Cipher(
    algorithms.AES(key),
    modes.ECB(),  # Don't use ECB in practice!
    backend=default_backend()
)

# Encrypt
encryptor = cipher.encryptor()
plaintext = b"Hello World 16B!"  # Exactly 16 bytes
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decrypt
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted:  {decrypted}")
```

---

## Modes of Operation {#modes-of-operation}

**Problem:** Block ciphers only encrypt one block. How to encrypt longer messages?

**Solution:** Modes of operation define how to apply block cipher to multi-block messages.

### 1. ECB (Electronic Codebook) - ⚠️ INSECURE

**How it works:**

```
Plaintext:  P₁    P₂    P₃    ...
              ↓     ↓     ↓
            [E_K] [E_K] [E_K]
              ↓     ↓     ↓
Ciphertext: C₁    C₂    C₃    ...
```

Each block encrypted independently with same key.

**Encryption:**
```
C_i = E_K(P_i)
```

**Decryption:**
```
P_i = D_K(C_i)
```

**Advantages:**
- Simple
- Parallelizable
- No IV needed
- Random access (can decrypt any block)

**Critical Flaws:**
1. **Identical plaintext blocks → identical ciphertext blocks**
2. **Patterns visible** (famous penguin example)
3. **Block reordering attacks**
4. **Block substitution attacks**

**Example Attack:**
```
Message: "TRANSFER $100 TO ALICE"
Blocks:  ["TRANSFER $10", "0 TO ALICE "]

Attacker intercepts and modifies:
Blocks:  ["TRANSFER $10", "00 TO ALICE"]  ← Changed one character
Result:  "TRANSFER $1000 TO ALICE"
```

**⚠️ NEVER USE ECB MODE IN PRACTICE!**

### 2. CBC (Cipher Block Chaining)

**How it works:**

```
IV ⊕ P₁ → [E_K] → C₁
C₁ ⊕ P₂ → [E_K] → C₂
C₂ ⊕ P₃ → [E_K] → C₃
...
```

Each plaintext block XORed with previous ciphertext before encryption.

**Encryption:**
```
C_0 = IV (Initialization Vector)
C_i = E_K(P_i ⊕ C_{i-1})
```

**Decryption:**
```
P_i = D_K(C_i) ⊕ C_{i-1}
```

**Properties:**
- **Requires IV:** Random, unique for each message
- **Not parallelizable (encryption):** Must wait for previous block
- **Parallelizable (decryption):** Can decrypt all blocks simultaneously
- **Error propagation:** 1-bit error affects current + next block

**IV Requirements:**
- **Random:** Unpredictable
- **Unique:** Never reuse with same key
- **Not secret:** Can be sent with ciphertext

**Security:**
- ✅ Identical plaintext blocks → different ciphertext
- ✅ Patterns hidden
- ⚠️ Padding oracle attacks possible
- ⚠️ No authentication (vulnerable to tampering)

**Use case:** General-purpose encryption (when GCM not available)

### 3. CTR (Counter Mode)

**How it works:**

```
Encrypt counter values, then XOR with plaintext:

Counter: [Nonce || 0] → [E_K] → K₁ ⊕ P₁ → C₁
Counter: [Nonce || 1] → [E_K] → K₂ ⊕ P₂ → C₂
Counter: [Nonce || 2] → [E_K] → K₃ ⊕ P₃ → C₃
```

Turns block cipher into stream cipher!

**Encryption:**
```
C_i = P_i ⊕ E_K(Nonce || Counter_i)
```

**Decryption (same as encryption):**
```
P_i = C_i ⊕ E_K(Nonce || Counter_i)
```

**Properties:**
- **Requires nonce:** Random, unique
- **Fully parallelizable:** Encrypt/decrypt any block
- **Random access:** Can decrypt block N without previous blocks
- **No padding needed:** Can handle any length
- **Precomputation:** Can encrypt counters before message arrives

**IV (Nonce + Counter):**
- Nonce: Random unique value
- Counter: Starts at 0, increments
- **Never reuse nonce** with same key!

**Security:**
- ✅ Very secure when used correctly
- ✅ Parallel processing
- ⚠️ Nonce reuse catastrophic (XOR plaintext recovery)
- ⚠️ No authentication

**Use case:** High-performance encryption, disk encryption

### 4. GCM (Galois/Counter Mode) - ✅ RECOMMENDED

**What it is:** CTR mode + authentication tag

**How it works:**

```
Encryption + Authentication:
1. Encrypt with CTR mode
2. Compute authentication tag over:
   - Ciphertext
   - Additional Authenticated Data (AAD)
   - Using GHASH function

Output: Ciphertext + Authentication Tag
```

**Structure:**
```
Plaintext → [CTR Encrypt] → Ciphertext
                               ↓
AAD + Ciphertext → [GHASH] → Authentication Tag
```

**Properties:**
- **Authenticated encryption:** Confidentiality + integrity
- **Additional Authenticated Data (AAD):** Authenticate without encrypting
- **Parallelizable:** Fast on modern hardware
- **AES-NI support:** Hardware acceleration

**Parameters:**
- **Key:** 128, 192, or 256 bits
- **Nonce:** 96 bits (12 bytes) recommended
- **Tag:** 128 bits (16 bytes) recommended
- **AAD:** Any length (e.g., headers, metadata)

**Security:**
- ✅ Confidentiality
- ✅ Integrity
- ✅ Authenticity
- ✅ Detects tampering
- ⚠️ Nonce reuse catastrophic

**Use case:** Modern applications (TLS 1.3, SSH, disk encryption)

### Mode Comparison

| Mode | Security | Speed | Parallel? | IV/Nonce | Padding? | Auth? |
|------|----------|-------|-----------|----------|----------|-------|
| **ECB** | ❌ Bad | Fast | ✅ Yes | None | ✅ Yes | ❌ No |
| **CBC** | ⚠️ OK | Medium | Decrypt only | Random IV | ✅ Yes | ❌ No |
| **CTR** | ✅ Good | Fast | ✅ Yes | Nonce | ❌ No | ❌ No |
| **GCM** | ✅ Best | Fast | ✅ Yes | Nonce | ❌ No | ✅ Yes |

**Recommendation:** **Use GCM mode** for new applications.

---

## Padding Schemes {#padding-schemes}

**Problem:** Block ciphers need exact block size. What if message isn't a multiple?

### PKCS#7 Padding

**Rule:** Add N bytes, each with value N

```
Examples (8-byte blocks):

Message: "HI"      (2 bytes)
Padded:  "HI" + 06 06 06 06 06 06    (8 bytes)

Message: "HELLO"   (5 bytes)
Padded:  "HELLO" + 03 03 03          (8 bytes)

Message: "12345678" (8 bytes - exactly one block)
Padded:  "12345678" + 08 08 08 08 08 08 08 08  (16 bytes - need full block!)
```

**Why add full block when message is exact size?**
- Unambiguous: Can always remove padding
- Otherwise: Can't tell if last byte is padding or data

**Removing padding:**
1. Read last byte value N
2. Verify last N bytes all equal N
3. Remove last N bytes

### Other Padding Schemes

**ISO/IEC 7816-4:**
```
Add 0x80, then 0x00 bytes
Example: "HELLO" + 80 00 00
```

**Zero Padding:**
```
Add 0x00 bytes
Problem: Ambiguous if data ends with 0x00
```

**Recommendation:** Use PKCS#7 or use mode that doesn't need padding (CTR, GCM)

---

## Security Considerations {#security-considerations}

### 1. Key Management

**Key generation:**
```python
import os
key = os.urandom(32)  # Use cryptographically secure RNG
```

**⚠️ DON'T:**
```python
key = b"password123" # Weak key
key = "secret".encode() # Predictable
```

**Key storage:**
- Never hardcode keys
- Use key derivation functions (PBKDF2, Argon2)
- Use hardware security modules (HSM) for high security
- Rotate keys regularly

### 2. IV/Nonce Management

**Requirements:**
- **Unique:** Never reuse with same key
- **Random:** For CBC (unpredictable)
- **Sequential OK:** For CTR/GCM (but never repeat)

**Common mistakes:**
```python
# ❌ BAD: Hardcoded IV
iv = b"0" * 16

# ❌ BAD: Reusing IV
encrypt(message1, key, iv)
encrypt(message2, key, iv)  # IV reused!

# ✅ GOOD: Random IV each time
iv = os.urandom(16)
```

### 3. Authentication

**Problem:** Encryption alone doesn't prevent tampering

**Solutions:**
1. **Use GCM mode** (authenticated encryption)
2. **Encrypt-then-MAC:** Encrypt, then HMAC the ciphertext
3. **Never use Encrypt-and-MAC or MAC-then-Encrypt**

### 4. Timing Attacks

**Problem:** Timing differences reveal information

**Example:** Comparing authentication tags
```python
# ❌ BAD: Stops at first mismatch
if computed_tag == received_tag:
    return True

# ✅ GOOD: Constant-time comparison
from hmac import compare_digest
if compare_digest(computed_tag, received_tag):
    return True
```

### 5. Side-Channel Attacks

**Types:**
- **Timing:** Measure execution time
- **Power analysis:** Measure power consumption
- **Cache attacks:** Observe CPU cache behavior

**Mitigation:**
- Use constant-time implementations
- Use AES-NI (hardware acceleration)
- Don't implement crypto yourself!

---

## Authenticated Encryption {#authenticated-encryption}

### Why Authentication Matters

**Encryption alone:**
- ✅ Confidentiality (secrecy)
- ❌ No integrity (can be modified)
- ❌ No authenticity (can be forged)

**Example attack (bit-flipping in CBC):**
```
Ciphertext block: C_i
Plaintext block:  P_i = D_K(C_i) ⊕ C_{i-1}

Attacker flips bit in C_{i-1}:
→ Same bit flipped in P_i!
```

### Authenticated Encryption (AE)

**Goal:** Provide confidentiality + integrity + authenticity

**Standard notation:** AEAD (Authenticated Encryption with Associated Data)

### AEAD Modes

#### AES-GCM (Recommended)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate key
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# Generate nonce (must be unique!)
nonce = os.urandom(12)  # 96 bits

# Encrypt with authentication
plaintext = b"Secret message"
associated_data = b"header"  # Authenticated but not encrypted
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# Decrypt and verify
decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
# Raises exception if authentication fails!
```

#### ChaCha20-Poly1305 (Alternative)

- Faster on systems without AES-NI
- Used in TLS 1.3
- Same AEAD interface

### Encrypt-then-MAC (Manual Alternative)

If GCM not available:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. Encrypt with CBC
cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
ciphertext = cipher.encryptor().update(plaintext)

# 2. MAC the ciphertext (and IV)
h = hmac.HMAC(mac_key, hashes.SHA256())
h.update(iv + ciphertext)
tag = h.finalize()

# Send: iv || ciphertext || tag
```

**⚠️ Important:** Use **separate keys** for encryption and MAC!

---

## Practical Guidelines {#practical-guidelines}

### What to Use

**For new applications:**
```
✅ AES-256-GCM
✅ ChaCha20-Poly1305
```

**If GCM not available:**
```
⚠️ AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
```

**Never use:**
```
❌ ECB mode
❌ DES
❌ RC4
❌ Any mode without authentication
```

### Key Sizes

| Algorithm | Minimum | Recommended |
|-----------|---------|-------------|
| AES | 128 bits | **256 bits** |
| HMAC | 256 bits | **256 bits** |

### Example: Secure File Encryption

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def encrypt_file(password: str, input_file: str, output_file: str):
    # 1. Derive key from password
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )
    key = kdf.derive(password.encode())
    
    # 2. Create AESGCM cipher
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # 3. Encrypt file
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # 4. Save: salt || nonce || ciphertext (with tag)
    with open(output_file, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

def decrypt_file(password: str, input_file: str, output_file: str):
    # 1. Read file
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()
    
    # 2. Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )
    key = kdf.derive(password.encode())
    
    # 3. Decrypt and verify
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    # 4. Save
    with open(output_file, 'wb') as f:
        f.write(plaintext)
```

---

## Comparison and Best Practices {#comparison-and-best-practices}

### Algorithm Comparison

| Feature | DES | 3DES | AES-128 | AES-256 |
|---------|-----|------|---------|---------|
| **Key size** | 56 bits | 168 bits | 128 bits | 256 bits |
| **Block size** | 64 bits | 64 bits | 128 bits | 128 bits |
| **Security** | ❌ Broken | ⚠️ OK | ✅ Secure | ✅ Very secure |
| **Speed** | Medium | Slow | Fast | Fast |
| **Status** | Deprecated | Deprecated | Recommended | Recommended |

### Best Practices Summary

1. **Algorithm:**
   - ✅ Use AES-256
   - ❌ Never use DES

2. **Mode:**
   - ✅ Use GCM (authenticated encryption)
   - ⚠️ Use CBC + HMAC if GCM not available
   - ❌ Never use ECB

3. **Keys:**
   - ✅ Generate with `os.urandom()`
   - ✅ Derive from passwords with PBKDF2/Argon2
   - ❌ Never hardcode keys

4. **IV/Nonce:**
   - ✅ Random and unique for each message
   - ✅ Store with ciphertext (not secret)
   - ❌ Never reuse with same key

5. **Authentication:**
   - ✅ Always authenticate ciphertext
   - ✅ Use GCM or Encrypt-then-MAC
   - ❌ Never use unauthenticated encryption

6. **Implementation:**
   - ✅ Use established libraries (cryptography, libsodium)
   - ✅ Keep libraries updated
   - ❌ Never implement crypto yourself

### Common Mistakes

1. **Using ECB mode**
   ```python
   # ❌ BAD
   cipher = Cipher(algorithms.AES(key), modes.ECB())
   ```

2. **Reusing IV/nonce**
   ```python
   # ❌ BAD
   iv = b"0" * 16
   cipher1 = Cipher(algorithms.AES(key), modes.CBC(iv))
   cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv))  # IV reused!
   ```

3. **No authentication**
   ```python
   # ❌ BAD
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
   ciphertext = cipher.encryptor().update(plaintext)
   # Attacker can modify ciphertext!
   ```

4. **Weak key derivation**
   ```python
   # ❌ BAD
   key = hashlib.sha256(password.encode()).digest()
   # Fast to brute force!
   
   # ✅ GOOD
   key = PBKDF2(password, salt, iterations=600_000)
   ```

### Security Checklist

Before deploying:

- [ ] Using AES-256-GCM or ChaCha20-Poly1305
- [ ] Keys generated with secure RNG
- [ ] Keys derived from passwords use PBKDF2/Argon2
- [ ] IV/nonce is random and unique for each encryption
- [ ] Using authenticated encryption
- [ ] Using established cryptography library
- [ ] Library is up to date
- [ ] Constant-time comparisons for tags/MACs
- [ ] Proper error handling (don't leak info)
- [ ] Secure key storage (not hardcoded)

---

## Practice Exercises

1. **Mode Comparison:**
   - Encrypt same image with ECB and CBC
   - Observe visual patterns in ECB
   - Why does CBC hide patterns?

2. **Padding Oracle:**
   - Implement PKCS#7 padding/unpadding
   - What happens with invalid padding?
   - How could this leak information?

3. **Nonce Reuse:**
   - Encrypt two different messages with same key/nonce in CTR mode
   - XOR the ciphertexts
   - What information is revealed?

4. **Authenticated Encryption:**
   - Implement file encryption with AES-GCM
   - Try modifying ciphertext
   - Verify it raises authentication error

5. **Performance:**
   - Benchmark AES-128 vs AES-256
   - Compare CBC vs CTR vs GCM
   - Which is fastest on your hardware?

---

## Next Steps

After mastering block ciphers:
1. Study **stream ciphers** (Crypto 3)
2. Learn **public-key cryptography** (Crypto 4)
3. Explore **TLS protocol** (how it uses AES-GCM)
4. Understand **key exchange** (Diffie-Hellman)
5. Practice with labs in `../../labs/`

---

## References

- **NIST AES:** https://csrc.nist.gov/publications/detail/fips/197/final
- **NIST Block Cipher Modes:** https://csrc.nist.gov/publications/detail/sp/800-38a/final
- **GCM Spec:** https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **Cryptography Engineering** by Ferguson, Schneier, Kohno
- **Serious Cryptography** by Jean-Philippe Aumasson

---

**Remember:** Use modern, authenticated encryption (AES-256-GCM) for all new applications! 🔒

