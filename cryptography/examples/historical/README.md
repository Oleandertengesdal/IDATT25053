# Historical Cryptography Examples

This directory contains implementations of classical ciphers for educational purposes. These examples demonstrate both how historical ciphers work and why they are insecure.

## ⚠️ Security Warning

**THESE CIPHERS ARE INSECURE AND SHOULD NEVER BE USED FOR REAL SECURITY.**

They are provided purely for educational purposes to understand:
- The evolution of cryptography
- Common attack techniques
- Why modern cryptography is necessary

## Contents

### 1. Caesar Cipher (`caesar_cipher.py`)

**What it is:** Simple substitution cipher shifting each letter by a fixed amount.

**Features:**
- Encryption/decryption
- Brute force attack (try all 26 shifts)
- Frequency analysis attack using chi-squared test
- Visual frequency distribution

**Run it:**
```bash
python caesar_cipher.py
```

**Key Concepts:**
- Substitution cipher
- Frequency analysis
- Chi-squared test
- Why keyspace size alone doesn't guarantee security

### 2. Vigenère Cipher (`vigenere_cipher.py`)

**What it is:** Polyalphabetic cipher using a keyword to create multiple Caesar shifts.

**Features:**
- Encryption/decryption with keyword
- Kasiski examination (finding keyword length)
- Index of Coincidence calculation
- Automatic cryptanalysis
- Frequency analysis per keyword position

**Run it:**
```bash
python vigenere_cipher.py
```

**Key Concepts:**
- Polyalphabetic substitution
- Kasiski examination
- Index of Coincidence (IC)
- Breaking down complex cipher into simpler components

**Attack Process:**
1. Find repeated sequences in ciphertext
2. Calculate distances between repetitions
3. Find GCD to determine likely keyword length
4. Split ciphertext by keyword position
5. Apply frequency analysis to each position (now just Caesar ciphers)

### 3. Enigma Machine (`enigma_simulation.py`)

**What it is:** Simplified simulation of the Enigma I machine used in WWII.

**Features:**
- 3 rotors with historical wirings
- Reflector (UKW-B)
- Plugboard (Steckerbrett)
- Rotor stepping mechanism (including double-stepping)
- Symmetric encryption (same process for encryption/decryption)

**Run it:**
```bash
python enigma_simulation.py
```

**Key Concepts:**
- Mechanical encryption
- Rotor-based cryptography
- Symmetry property (if A→X then X→A)
- Fatal flaw: letter never encrypts to itself
- Keyspace: ~10^23 (seems large, but broken!)

**How Enigma Was Broken:**
1. **Cribs:** Known/guessed plaintext phrases
2. **No self-encryption:** Letter never maps to itself (due to reflector)
3. **Bombe machine:** Automated testing of rotor settings
4. **Operator errors:** Weak key choices, repeated settings
5. **Captured materials:** Codebooks and machines

## Running the Examples

All examples include:
- **Demonstrations:** Run the file to see automatic demonstrations
- **Interactive mode:** Hands-on encryption/decryption/cryptanalysis
- **Educational output:** Explanations and security warnings

## Learning Objectives

After working through these examples, you should understand:

1. **Historical Context:**
   - How cryptography evolved before computers
   - Ingenuity of mechanical encryption (Enigma)
   - Impact of cryptanalysis on history (WWII)

2. **Attack Techniques:**
   - Brute force (trying all keys)
   - Frequency analysis (exploiting language statistics)
   - Known/chosen plaintext attacks (using cribs)
   - Statistical methods (chi-squared, IC)

3. **Why They Failed:**
   - Caesar: Tiny keyspace (26), frequency preserved
   - Vigenère: Reduces to multiple Caesar ciphers
   - Enigma: No self-encryption, cribs, limited keyspace

4. **Modern Lessons:**
   - Need for large keyspaces (AES-256: 2^256)
   - Must be secure even if algorithm is known (Kerckhoffs's principle)
   - Proper randomness essential
   - Need authenticated encryption (not just confidentiality)

## Comparison Table

| Cipher | Keyspace | Secure? | Main Weakness |
|--------|----------|---------|---------------|
| Caesar | 26 | ❌ No | Tiny keyspace, frequency analysis |
| Vigenère | 26^n | ❌ No | Kasiski examination, IC test |
| Enigma | ~10^23 | ❌ No | No self-encryption, cribs |
| **AES-256** | **2^256 ≈ 10^77** | **✅ Yes** | **None known** |

## Modern Alternatives

For real security, use:
- **AES-256-GCM:** Symmetric encryption
- **RSA-4096 or ECC:** Asymmetric encryption
- **Argon2 or bcrypt:** Password hashing
- **TLS 1.3:** Secure communications

See the `../symmetric/` and `../asymmetric/` directories for modern examples.

## Exercises

Try these to deepen your understanding:

1. **Caesar Cipher:**
   - Encrypt a message with shift 7
   - Break it using brute force
   - Break it using frequency analysis
   - Which method is faster?

2. **Vigenère Cipher:**
   - Create a long text (200+ characters)
   - Encrypt with keyword "CRYPTO"
   - Use Kasiski examination to find keyword length
   - Calculate IC for ciphertext vs plaintext

3. **Enigma:**
   - Configure Enigma with rotors (I, II, III) at (Q, E, V)
   - Encrypt "ATTACK AT DAWN"
   - Verify symmetry: decrypt the ciphertext with same settings
   - Change one rotor position - how much does output change?

4. **Comparison:**
   - Encrypt same message with all three ciphers
   - Try to break each one
   - Which is hardest? Why?
   - Would any be secure with modern key lengths?

## References

- **Kerckhoffs's Principle:** [Wikipedia](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)
- **Frequency Analysis:** [Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography)
- **Enigma Machine:** [Crypto Museum](https://www.cryptomuseum.com/crypto/enigma/)
- **Breaking Enigma:** [Alan Turing: The Enigma](https://en.wikipedia.org/wiki/Alan_Turing)

## Next Steps

Once you understand these classical ciphers:
1. Study `../../theory/crypto2_block_ciphers.md` for modern symmetric crypto
2. Try examples in `../symmetric/` directory
3. Learn about authenticated encryption (AES-GCM)
4. Understand why modern crypto is fundamentally different

---

**Remember:** These are EDUCATIONAL examples. Never use these for real security! 🔒
