# Crypto 1: Introduction to Cryptography

## 📚 Overview

Cryptography is the science of securing communication and information through mathematical techniques. This module introduces fundamental concepts, historical context, and basic principles that underpin all modern cryptographic systems.

---

## 🎯 Learning Objectives

By completing this module, you will:

1. Understand the historical evolution of cryptography
2. Implement and break classical ciphers (Caesar, Vigenère)
3. Comprehend fundamental cryptographic principles
4. Distinguish between confidentiality, integrity, and authenticity
5. Understand Kerckhoffs's principle and its importance
6. Recognize basic cryptanalysis techniques

---

## 📖 Table of Contents

1. [What is Cryptography?](#what-is-cryptography)
2. [Historical Ciphers](#historical-ciphers)
3. [Fundamental Concepts](#fundamental-concepts)
4. [Kerckhoffs's Principle](#kerckhoffs-principle)
5. [Key Management Basics](#key-management-basics)
6. [Introduction to Cryptanalysis](#introduction-to-cryptanalysis)

---

## 🔐 What is Cryptography?

### Definition

**Cryptography** (from Greek: *kryptós* "hidden" + *gráphein* "to write") is the practice and study of techniques for secure communication in the presence of adversaries.

### Core Goals

1. **Confidentiality**: Only authorized parties can read the message
2. **Integrity**: Message cannot be altered without detection
3. **Authenticity**: Verify sender's identity
4. **Non-repudiation**: Sender cannot deny sending the message

### Basic Terminology

| Term | Definition | Example |
|------|------------|---------|
| **Plaintext** | Original, readable message | "HELLO WORLD" |
| **Ciphertext** | Encrypted, unreadable message | "KHOOR ZRUOG" |
| **Encryption** | Process of converting plaintext to ciphertext | `E(plaintext, key) → ciphertext` |
| **Decryption** | Process of converting ciphertext back to plaintext | `D(ciphertext, key) → plaintext` |
| **Key** | Secret parameter used in encryption/decryption | 3 (for Caesar cipher) |
| **Cipher** | Algorithm for encryption/decryption | Caesar, AES, RSA |
| **Cryptanalysis** | Study of breaking ciphers | Frequency analysis |

### Mathematical Model

**Encryption**: $C = E_k(P)$  
**Decryption**: $P = D_k(C)$  

Where:
- $P$ = Plaintext
- $C$ = Ciphertext
- $k$ = Key
- $E$ = Encryption function
- $D$ = Decryption function

**Property**: $D_k(E_k(P)) = P$ (decryption reverses encryption)

---

## 🏛️ Historical Ciphers

### 1. Caesar Cipher (Substitution Cipher)

#### History

Named after Julius Caesar, who used it to protect military messages around 50 BC. Each letter is shifted by a fixed number of positions in the alphabet.

#### How It Works

**Encryption**: Shift each letter forward by *n* positions  
**Decryption**: Shift each letter backward by *n* positions

**Example** (shift of 3):
```
Plaintext:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Ciphertext: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C

Plaintext:  HELLO WORLD
Ciphertext: KHOOR ZRUOG
```

#### Mathematical Representation

For alphabet position $x$ (A=0, B=1, ..., Z=25):

**Encryption**: $C = (P + k) \mod 26$  
**Decryption**: $P = (C - k) \mod 26$

Where $k$ is the shift value.

#### Security Analysis

**Weaknesses**:
- Only 26 possible keys (easily brute-forced)
- No protection against frequency analysis
- Pattern preservation (repeated letters stay repeated)

**Breaking Caesar Cipher**:
1. **Brute Force**: Try all 26 shifts
2. **Frequency Analysis**: Most common letter likely 'E' in English
3. **Known Plaintext**: If you know any plaintext-ciphertext pair

#### Implementation

See `examples/historical/caesar_cipher.py` for full implementation.

**Simple Python Example**:
```python
def caesar_encrypt(plaintext, shift):
    """Encrypt using Caesar cipher."""
    result = ""
    for char in plaintext.upper():
        if char.isalpha():
            # Shift character (A=0, Z=25)
            shifted = (ord(char) - ord('A') + shift) % 26
            result += chr(shifted + ord('A'))
        else:
            result += char  # Keep non-letters unchanged
    return result

def caesar_decrypt(ciphertext, shift):
    """Decrypt Caesar cipher."""
    return caesar_encrypt(ciphertext, -shift)

# Example usage
plaintext = "HELLO WORLD"
shift = 3
ciphertext = caesar_encrypt(plaintext, shift)
print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext}")  # Output: KHOOR ZRUOG
print(f"Decrypted:  {caesar_decrypt(ciphertext, shift)}")
```

---

### 2. Vigenère Cipher (Polyalphabetic Cipher)

#### History

Invented by Giovan Battista Bellaso in 1553, but misattributed to Blaise de Vigenère. Considered unbreakable for 300 years ("le chiffre indéchiffrable").

#### How It Works

Uses a **keyword** to determine multiple Caesar shifts. Each letter in the keyword represents a shift value.

**Process**:
1. Repeat keyword to match plaintext length
2. For each position, shift by the corresponding keyword letter's value

**Example** (keyword: "KEY"):
```
Plaintext:  H E L L O W O R L D
Keyword:    K E Y K E Y K E Y K
Shifts:     10 4 24 10 4 24 10 4 24 10
Ciphertext: R I J V S P Y V J N
```

#### Mathematical Representation

For plaintext $P_i$ and keyword letter $K_i$:

**Encryption**: $C_i = (P_i + K_i) \mod 26$  
**Decryption**: $P_i = (C_i - K_i) \mod 26$

Where keyword repeats: $K_i = K_{i \mod \text{keyword\_length}}$

#### Security Analysis

**Strengths**:
- More keys than Caesar (keyword can be any length/word)
- Frequency analysis doesn't work directly
- Same plaintext letter → different ciphertext letters

**Weaknesses**:
- **Vulnerable to Kasiski examination** (finds keyword length)
- **Friedman test** (statistical method)
- Once keyword length found, reduces to multiple Caesar ciphers

**Breaking Vigenère**:
1. **Find keyword length**:
   - Look for repeated patterns in ciphertext
   - Distance between repetitions likely divisor of keyword length
2. **Split ciphertext** into groups (one per keyword position)
3. **Frequency analysis** on each group (like breaking Caesar)

#### Implementation

See `examples/historical/vigenere_cipher.py` for full implementation.

**Python Example**:
```python
def vigenere_encrypt(plaintext, keyword):
    """Encrypt using Vigenère cipher."""
    result = ""
    keyword = keyword.upper()
    keyword_index = 0
    
    for char in plaintext.upper():
        if char.isalpha():
            # Get shift from keyword
            shift = ord(keyword[keyword_index % len(keyword)]) - ord('A')
            # Encrypt character
            encrypted = (ord(char) - ord('A') + shift) % 26
            result += chr(encrypted + ord('A'))
            keyword_index += 1
        else:
            result += char
    
    return result

def vigenere_decrypt(ciphertext, keyword):
    """Decrypt Vigenère cipher."""
    result = ""
    keyword = keyword.upper()
    keyword_index = 0
    
    for char in ciphertext.upper():
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)]) - ord('A')
            decrypted = (ord(char) - ord('A') - shift) % 26
            result += chr(decrypted + ord('A'))
            keyword_index += 1
        else:
            result += char
    
    return result

# Example
plaintext = "HELLO WORLD"
keyword = "KEY"
ciphertext = vigenere_encrypt(plaintext, keyword)
print(f"Plaintext:  {plaintext}")
print(f"Keyword:    {keyword}")
print(f"Ciphertext: {ciphertext}")  # Output: RIJVSPYVJN
```

---

### 3. Enigma Machine (Rotor Cipher)

#### History

Invented by German engineer Arthur Scherbius in 1918. Used extensively by Nazi Germany during World War II. Breaking Enigma (by Alan Turing and team at Bletchley Park) significantly contributed to Allied victory.

#### How It Works

**Components**:
1. **Keyboard**: Input plaintext
2. **Plugboard**: Initial letter substitution (10 pairs)
3. **Rotors** (3-5): Rotating substitution wheels
4. **Reflector**: Sends signal back through rotors
5. **Lampboard**: Displays ciphertext

**Process**:
1. Press key on keyboard
2. Signal passes through plugboard
3. Signal passes through rotors (right to left)
4. Signal reflects and passes back through rotors
5. Signal passes through plugboard again
6. Lamp lights up with ciphertext letter
7. **Rotors advance** (right rotor every keystroke, middle rotor after full rotation, etc.)

**Key Components**:
- **Rotor positions**: Initial setting (e.g., "AAA")
- **Ring settings**: Offset of internal wiring
- **Plugboard**: 10 letter pairs swapped
- **Rotor order**: Which rotors in which slots

#### Mathematical Complexity

**Keyspace**:
- Rotor order: $5 \times 4 \times 3 = 60$ ways
- Rotor positions: $26^3 = 17,576$ combinations
- Ring settings: $26^3 = 17,576$ combinations
- Plugboard: $\approx 150$ trillion combinations

**Total**: $\approx 159$ quintillion possible settings

#### Security Analysis

**Strengths**:
- Enormous keyspace (for its time)
- Rotors move with each keystroke (polyalphabetic on steroids)
- Self-inverse property (same setting encrypts/decrypts)

**Weaknesses**:
- **No letter encrypts to itself** (design flaw in reflector)
- Repeated settings led to patterns
- Operator errors revealed information
- Known message formats ("WEATHER REPORT")

**Breaking Enigma**:
1. **Cribs**: Known plaintext fragments (e.g., "WETTER" = weather)
2. **Bombe machine**: Electromechanical device to test settings
3. **Statistical analysis**: Exploit patterns from operator mistakes
4. **Intelligence**: Captured codebooks and machines

#### Simplified Simulation

See `examples/historical/enigma_simulation.py` for educational simulation.

---

## 🧮 Fundamental Concepts

### 1. Confidentiality, Integrity, Authenticity (CIA+ Triad)

#### Confidentiality

**Definition**: Information is accessible only to authorized parties.

**Achieved by**: Encryption

**Example**: Encrypting email so only recipient can read it.

**Threat**: Eavesdropping, unauthorized access

#### Integrity

**Definition**: Information cannot be modified without detection.

**Achieved by**: Hash functions, MACs (Message Authentication Codes)

**Example**: File checksums detect if file was tampered with.

**Threat**: Tampering, data corruption

#### Authenticity

**Definition**: Verify the identity of the sender.

**Achieved by**: Digital signatures, MACs

**Example**: Digital signature proves email is from claimed sender.

**Threat**: Impersonation, spoofing

#### Non-Repudiation (Additional)

**Definition**: Sender cannot deny sending the message.

**Achieved by**: Digital signatures with public-key infrastructure

**Example**: Signed contract cannot be denied later.

### 2. Kerckhoffs's Principle

#### Statement

> **"A cryptosystem should be secure even if everything about the system, except the key, is public knowledge."**  
> — Auguste Kerckhoffs, 1883

#### Modern Formulation (Shannon's Maxim)

> **"The enemy knows the system."**  
> — Claude Shannon, 1949

#### What This Means

**Security should rely ONLY on the secrecy of the key**, not on:
- ❌ Secret algorithm design
- ❌ Obscure implementation
- ❌ Hidden system architecture

**Why?**
- Algorithms get reverse-engineered
- "Security through obscurity" fails when discovered
- Public algorithms receive more scrutiny and are more trustworthy

#### Practical Implications

✅ **DO**:
- Use published, peer-reviewed algorithms (AES, RSA)
- Keep keys secret and change them regularly
- Assume attacker knows your encryption method

❌ **DON'T**:
- Create your own "secret" encryption algorithm
- Rely on keeping the algorithm hidden
- Think obscurity equals security

#### Examples

**Good** (Kerckhoffs-compliant):
- AES encryption with secret key
- RSA with secret private key
- Published TLS protocol

**Bad** (security through obscurity):
- Custom XOR cipher "no one knows about"
- Obfuscated code as encryption
- Hidden file format

---

## 🔑 Key Management Basics

### Key Generation

**Requirements**:
- **Random**: Keys must be unpredictable
- **Sufficient length**: Resist brute force
- **Unique**: Different keys for different purposes

**Methods**:
- **Cryptographically Secure Random Number Generator (CSRNG)**
- **Key Derivation Functions (KDF)** from passwords
- **Hardware Random Number Generators (HRNG)**

### Key Storage

**Never**:
- ❌ Hardcode keys in source code
- ❌ Store keys in plain text files
- ❌ Share keys via insecure channels

**Instead**:
- ✅ Use environment variables
- ✅ Key management systems (AWS KMS, Azure Key Vault)
- ✅ Hardware Security Modules (HSM)
- ✅ Encrypted key stores

### Key Distribution

**Problem**: How to share keys securely?

**Solutions**:
- **Pre-shared keys**: Exchange in person (impractical at scale)
- **Public-key cryptography**: Solve key distribution (Crypto 4)
- **Key exchange protocols**: Diffie-Hellman (Crypto 4)

### Key Lifecycle

1. **Generation**: Create strong, random key
2. **Distribution**: Securely share with authorized parties
3. **Usage**: Encrypt/decrypt data
4. **Rotation**: Periodically replace keys
5. **Retirement**: Securely destroy old keys

---

## 🔍 Introduction to Cryptanalysis

### What is Cryptanalysis?

**Definition**: The study of analyzing and breaking cryptographic systems.

**Goal**: Recover plaintext or key without authorized access.

### Types of Attacks

#### 1. Ciphertext-Only Attack

**Attacker has**: Ciphertext only  
**Goal**: Recover plaintext or key

**Example**: Intercepted encrypted message

**Defenses**: Strong ciphers that resist statistical analysis

#### 2. Known-Plaintext Attack

**Attacker has**: Plaintext-ciphertext pairs  
**Goal**: Recover key or decrypt other messages

**Example**: Encrypted email where attacker knows some content

**Historical**: Helped break Enigma (known phrases like "WEATHER REPORT")

#### 3. Chosen-Plaintext Attack

**Attacker can**: Choose plaintexts and get corresponding ciphertexts  
**Goal**: Recover key

**Example**: Oracle that encrypts any message you provide

**Modern relevance**: Important for evaluating algorithm security

#### 4. Chosen-Ciphertext Attack

**Attacker can**: Choose ciphertexts and get corresponding plaintexts  
**Goal**: Recover key or decrypt target ciphertext

**Example**: Padding oracle attacks on encryption

### Basic Cryptanalysis Techniques

#### Frequency Analysis

**How it works**:
1. Count letter frequencies in ciphertext
2. Compare to known language frequencies
3. Map most common ciphertext letters to most common plaintext letters

**English letter frequencies**:
- Most common: E, T, A, O, I, N
- Least common: Z, Q, X, J

**Effective against**:
- Caesar cipher
- Simple substitution ciphers
- Monoalphabetic ciphers

**Ineffective against**:
- Polyalphabetic ciphers (Vigenère)
- Modern ciphers (AES, RSA)

#### Pattern Recognition

**Look for**:
- Repeated sequences
- Common word patterns
- Double letters (TH, HE, AN in English)

**Example**: "HELLO" encrypted with same key → same ciphertext pattern

#### Statistical Analysis

**Techniques**:
- **Index of Coincidence**: Measures randomness
- **Chi-squared test**: Compares observed vs. expected frequencies
- **Kasiski examination**: Finds Vigenère keyword length

---

## 📊 Comparison of Historical Ciphers

| Cipher | Key Space | Security | Speed | Breaking Method |
|--------|-----------|----------|-------|-----------------|
| **Caesar** | 26 | Very weak | Very fast | Brute force, frequency analysis |
| **Vigenère** | $26^{\text{keyword length}}$ | Weak-Moderate | Fast | Kasiski, frequency analysis |
| **Enigma** | $\approx 10^{23}$ | Strong (for 1940s) | Mechanical | Cribs, Bombe machine, known plaintext |

---

## 🎯 Key Takeaways

1. **Historical ciphers are educational** but **not secure** for modern use
2. **Kerckhoffs's Principle**: Security must rely on key secrecy, not algorithm secrecy
3. **Frequency analysis** breaks simple substitution ciphers
4. **Key management** is as important as the algorithm itself
5. **Cryptanalysis** techniques help us understand cipher weaknesses
6. **Modern cryptography** builds on historical lessons

---

## 📝 Practice Exercises

### Exercise 1: Caesar Cipher

1. Encrypt "CRYPTOGRAPHY IS FUN" with shift 7
2. Decrypt "WKLV LV D PHVVDJH" (shift unknown - try brute force)
3. Use frequency analysis to break a longer Caesar-encrypted text

### Exercise 2: Vigenère Cipher

1. Encrypt "ATTACK AT DAWN" with keyword "CIPHER"
2. Decrypt "RIJVS PYVJN" with keyword "KEY"
3. Find repeated patterns in ciphertext and estimate keyword length

### Exercise 3: Implementation

Write Python functions to:
1. Implement Vigenère encryption/decryption
2. Perform frequency analysis on English text
3. Brute-force a Caesar cipher

**Solutions available in**: `examples/historical/`

---

## 📚 Further Reading

**Books**:
- *The Code Book* by Simon Singh (history of cryptography)
- *Introduction to Modern Cryptography* by Katz & Lindell

**Online**:
- [Crypto101](https://www.crypto101.io/) - Free cryptography book
- [Khan Academy: Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography)

**Historical**:
- [Enigma Machine Simulator](https://enigma.louisedade.co.uk/)
- [Crypto Museum](https://www.cryptomuseum.com/)

---

**Next Module**: [Crypto 2: Block Ciphers](./crypto2_block_ciphers.md)

---

**Last Updated**: October 14, 2025  
**Version**: 1.0
