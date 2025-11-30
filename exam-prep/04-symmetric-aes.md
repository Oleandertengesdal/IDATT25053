# 4. Symmetric Ciphers & AES - Complete Guide

## Overview
Focus on **concepts** rather than implementation details. Know confusion/diffusion, block modes, and key management.

---

## 4.1 Symmetric Encryption Basics

### Definition
Same key used for encryption and decryption.

```
Encryption: C = E_k(P)
Decryption: P = D_k(C)

where k is the shared secret key
```

### Stream vs Block Ciphers

**Exam Question:** "What is the difference between stream and block ciphers?"

**Model Answer:**
"Stream ciphers encrypt data bit-by-bit or byte-by-byte, typically by XORing plaintext with a pseudorandom keystream (e.g., ChaCha20). They are fast and suitable for streaming data but vulnerable if keystream repeats. Block ciphers encrypt fixed-size blocks (e.g., AES uses 128-bit blocks), requiring padding for incomplete blocks and a mode of operation for multiple blocks. Block ciphers are more versatile and widely standardized but slightly slower. Stream ciphers excel in constrained environments, while block ciphers dominate in general applications."

**Comparison:**
```
Property        | Stream Cipher    | Block Cipher
----------------|------------------|------------------
Processing      | Bit/byte at time | Fixed blocks
Speed           | Very fast        | Fast
Padding needed  | No               | Yes
Example         | ChaCha20, RC4    | AES, 3DES
Use case        | Real-time data   | General purpose
```

---

## 4.2 Confusion and Diffusion

### Shannon's Principles

**Confusion:** Relationship between key and ciphertext should be complex.
**Diffusion:** Each plaintext bit should affect many ciphertext bits.

### Example 1: Confusion

**Exam Question:** "Explain confusion in AES."

**Answer:**
```
Confusion means changing one key bit should drastically change the ciphertext
in unpredictable ways. AES achieves this through:

1. SubBytes (S-box):
   - Non-linear substitution
   - Input byte → completely different output byte
   - No linear relationship

Example:
Key bit flip: 0x2B → 0x2A (1 bit change)
After S-box: Output changes completely, not just 1 bit

2. AddRoundKey:
   - XORs key material into state
   - Key changes propagate through non-linear S-boxes
   - Makes key-ciphertext relationship opaque

Without confusion: key bits would have predictable effects,
enabling statistical attacks to recover keys.
```

### Example 2: Diffusion

**Exam Question:** "Explain diffusion in AES."

**Answer:**
```
Diffusion means changing one plaintext bit should affect many ciphertext bits.
AES achieves this through:

1. ShiftRows:
   - Rotates rows of state matrix
   - Spreads bytes across columns
   
2. MixColumns:
   - Matrix multiplication in GF(2^8)
   - Each output byte depends on all 4 input bytes
   - One changed input affects entire column

Example:
Input:  [01 00 00 00]  (1 bit set)
After 1 round: [XX XX XX XX]  (all bytes affected)
After 10 rounds: Completely scrambled

Without diffusion: could attack each part of block independently,
breaking cipher into smaller problems.
```

### Combined Effect
```
Round 1:  Plaintext change affects few bits  (local)
Round 2:  Spreads to more bits               (diffusion)
Round 3:  Complex key-dependent changes      (confusion)
...
Round 10: Complete "avalanche effect"

Avalanche: Flipping 1 input bit changes ~50% of output bits
```

---

## 4.3 Block Cipher Modes of Operation

### ECB (Electronic Codebook) - ❌ INSECURE

**Never use in practice!**

```
C₁ = E_k(P₁)
C₂ = E_k(P₂)
...

Problem: Identical plaintext blocks → identical ciphertext blocks
```

**Example 3: ECB Weakness**
```
Plaintext:  "HELLO HELLO WORLD"
Blocks:     "HELLO" "HELLO" "WORLD"
Ciphertext: "X7R2A" "X7R2A" "P9Z1Q"
                      ↑↑↑↑↑
                  Reveals pattern!

Famous: ECB penguin (encrypted image still shows penguin outline)
```

### CBC (Cipher Block Chaining) - ✅ SECURE

```
C₀ = IV (random initialization vector)
C₁ = E_k(P₁ ⊕ C₀)
C₂ = E_k(P₂ ⊕ C₁)
...

Decryption:
P₁ = D_k(C₁) ⊕ C₀
P₂ = D_k(C₂) ⊕ C₁
```

**Example 4: CBC Encryption**
```
Key = "SECRET KEY123456"
IV = random_128_bits()
Plaintext blocks: "HELLO" "WORLD"

Block 1:
temp = "HELLO" ⊕ IV
C₁ = AES_encrypt(temp, key)

Block 2:
temp = "WORLD" ⊕ C₁
C₂ = AES_encrypt(temp, key)

Send: (IV, C₁, C₂)
```

**CBC Bit-Flipping Attack:**
```
Since P₁ = D_k(C₁) ⊕ IV:

If attacker flips bit i in IV:
IV' = IV ⊕ (1 << i)

Then: P₁' = D_k(C₁) ⊕ IV'
          = D_k(C₁) ⊕ IV ⊕ (1 << i)
          = P₁ ⊕ (1 << i)

Bit i in plaintext is flipped!

Mitigation: Use authenticated encryption (GCM)
```

### CTR (Counter Mode) - ✅ SECURE

```
C₁ = P₁ ⊕ E_k(nonce || counter_1)
C₂ = P₂ ⊕ E_k(nonce || counter_2)
...

Properties:
- Parallel encryption/decryption
- No padding needed
- Turns block cipher into stream cipher
```

**Example 5: CTR Mode**
```
Nonce = random_64_bits()
Counter starts at 0

Block 1:
keystream₁ = AES_encrypt(nonce || 0, key)
C₁ = P₁ ⊕ keystream₁

Block 2:
keystream₂ = AES_encrypt(nonce || 1, key)
C₂ = P₂ ⊕ keystream₂

Decryption is identical:
P₁ = C₁ ⊕ keystream₁

CRITICAL: Never reuse (nonce, counter) pair!
```

### GCM (Galois/Counter Mode) - ✅ RECOMMENDED

Authenticated encryption: provides confidentiality + integrity.

```
Combines:
- CTR mode for encryption
- GMAC for authentication tag

Output: (ciphertext, authentication_tag)

Verification fails → reject message (tampered/forged)
```

---

## 4.4 Randomness

### True vs Pseudo-Random

**Exam Question:** "Difference between true and pseudo-random?"

**Answer:**
```
True Randomness:
- Unpredictable physical source (thermal noise, radioactive decay)
- Cannot be reproduced
- Examples: /dev/random (with hardware RNG), RDRAND instruction
- Use for: cryptographic keys, IVs, nonces

Pseudo-Randomness:
- Deterministic algorithm from seed
- Reproducible given same seed
- Passes statistical tests but predictable if seed known
- Examples: PRNG (Mersenne Twister), CSPRNG (ChaCha20)
- Use for: simulations, games, non-security random data

Security Impact:
Weak randomness in crypto keys → predictable keys → total failure
Example: Debian OpenSSL bug (2008) - weak PRNG, all keys predictable
```

### Example 6: Bad Randomness
```
❌ Bad: Using time as seed
srand(time(NULL));
key = rand();
// Only 2^32 possible keys! Brute forceable.

✅ Good: Use cryptographic RNG
key = os.urandom(32)  # Python
// Unpredictable, properly seeded from OS entropy pool
```

---

## 4.5 Key Management

### Key Derivation

**Exam Question:** "Why use KDF instead of hashing password directly?"

**Answer:**
```
Password → Hash vs Password → KDF

Direct hash:
- Fast (bad for passwords!)
- Vulnerable to brute force
- Example: SHA-256(password) - billions of attempts/sec on GPU

KDF (Key Derivation Function):
- Intentionally slow
- Memory-hard (resist GPU attacks)
- Includes salt (prevent rainbow tables)
- Configurable cost factor

Example: Argon2id(password, salt, time=3, memory=64MB)
- Takes ~0.5 seconds per attempt
- Drastically slows brute force
- Adjustable as hardware improves
```

### Forward Secrecy

**Exam Question:** "What is forward secrecy?"

**Answer:**
```
Forward secrecy means compromising long-term keys doesn't compromise
past session keys. Achieved by:

1. Generate ephemeral (temporary) keys for each session
2. Exchange using Diffie-Hellman
3. Delete ephemeral keys after session
4. Long-term keys only sign, never encrypt

Example: TLS 1.3
- Client and server generate random DH key pairs
- Exchange public keys
- Derive shared session key
- Delete private DH keys
- Even if server's private signing key stolen later,
  attacker cannot decrypt past sessions

Without forward secrecy (RSA key exchange):
- Sessions encrypted with server's public RSA key
- If private key stolen, all recorded sessions can be decrypted
```

### Session Keys

**Exam Question:** "Why use session keys?"

**Answer:**
```
Session keys are temporary keys for single communication session:

Benefits:
1. Limited exposure: compromise affects only one session
2. Performance: faster symmetric crypto after initial key exchange
3. Forward secrecy: deleted after use
4. Reduce key reuse risks

Example: TLS handshake
1. Authenticate with certificates (asymmetric - slow)
2. Establish session key (key exchange)
3. Use session key for data (symmetric - fast)
4. Delete session key after connection closes

Master key: Protects long-term identity
Session key: Protects specific conversation
```

---

## 4.6 AES Specifics

### AES Parameters
```
Key Size    | Rounds | Security Level
------------|--------|----------------
AES-128     | 10     | 128-bit
AES-192     | 12     | 192-bit
AES-256     | 14     | 256-bit

Block size: Always 128 bits (16 bytes)
```

### AES Structure
```
Each round (except last):
1. SubBytes - Confusion (S-box)
2. ShiftRows - Diffusion (row permutation)
3. MixColumns - Diffusion (column mixing)
4. AddRoundKey - Confusion (XOR round key)

Last round: Skip MixColumns
```

### Example 7: AES vs 3DES

**Exam Question:** "Why prefer AES over 3DES?"

**Answer:**
```
3DES (Triple DES):
- Block size: 64 bits (too small - birthday attacks)
- Key size: 112-168 bits effective
- Speed: ~3x slower than AES
- Deprecated since 2023

AES:
- Block size: 128 bits (secure)
- Key size: 128/192/256 bits
- Speed: Hardware acceleration (AES-NI)
- Modern design: resistant to known attacks

Security: Birthday attack on 64-bit blocks:
After 2^32 blocks (~32GB), collision likely
AES-128: Safe until 2^64 blocks (~ 295 million TB)
```

---

## 🎯 Exam Tips for Symmetric Ciphers

### Key Concepts to Explain Well

1. **Confusion vs Diffusion**
   - Always give examples
   - Explain what attack each prevents
   
2. **Mode Selection**
   - Know when to use each mode
   - Understand security properties
   
3. **Randomness**
   - True vs pseudo
   - Why it matters
   
4. **Key Management**
   - Derivation, rotation, forward secrecy
   - Session vs long-term keys

### Common Questions

**"Which mode should you use?"**
```
✅ GCM - Authenticated encryption (best default)
✅ CTR - If you add separate MAC
✅ CBC - Classic choice, but add HMAC
❌ ECB - Never, shows patterns
```

**"Why not reuse IV in CBC?"**
```
Same IV + Same key + Same first block
= Same first ciphertext block
= Reveals when messages start the same
```

---

## 📝 Quick Reference

```
BLOCK MODES:
ECB: C = E(P) - ❌ Insecure (patterns visible)
CBC: C = E(P ⊕ IV/Prev_C) - ✅ Secure with random IV
CTR: C = P ⊕ E(nonce||ctr) - ✅ Parallel, stream-like
GCM: CTR + MAC - ✅✅ Best (authenticated)

PRINCIPLES:
Confusion: Key → Ciphertext relationship complex (S-boxes)
Diffusion: One bit → affects many bits (permutations, mixing)

RANDOMNESS:
True: Physical source, unpredictable
Pseudo: Deterministic from seed, reproducible
Crypto needs: True randomness for keys/IVs

KEY MANAGEMENT:
KDF: Slow, salted key derivation (Argon2, PBKDF2)
Forward Secrecy: Past sessions safe if long-term key compromised
Session Keys: Temporary keys per session, then deleted
```

---

[← Previous: MAC & Hash](./03-mac-hash.md) | [Next: Buffer Overflow →](./05-buffer-overflow.md)
