# 1. Classical Ciphers - Complete Guide

## Overview
Classical ciphers appear in **EVERY exam**. You must be able to:
- Perform manual calculations with modulo 26
- Encrypt and decrypt messages
- Write and use mathematical formulas
- Understand CBC mode and XOR operations

---

## 1.1 Shift/Rotation Cipher (Caesar Cipher)

### Theory
The simplest cipher - shifts each letter by a fixed amount.

**Formula:**
```
Encryption: c = (m + k) mod 26
Decryption: m = (c - k) mod 26

where:
- m = plaintext letter (A=0, B=1, ..., Z=25)
- c = ciphertext letter
- k = shift key
```

### Example 1: Basic Encryption
**Question:** Encrypt "HELLO" with key k=3

**Solution:**
```
H = 7  → (7 + 3) mod 26 = 10 → K
E = 4  → (4 + 3) mod 26 = 7  → H
L = 11 → (11 + 3) mod 26 = 14 → O
L = 11 → (11 + 3) mod 26 = 14 → O
O = 14 → (14 + 3) mod 26 = 17 → R

Answer: "KHOOR"
```

### Example 2: Wrap-around
**Question:** Encrypt "XYZ" with key k=5

**Solution:**
```
X = 23 → (23 + 5) mod 26 = 28 mod 26 = 2 → C
Y = 24 → (24 + 5) mod 26 = 29 mod 26 = 3 → D
Z = 25 → (25 + 5) mod 26 = 30 mod 26 = 4 → E

Answer: "CDE"
```

### Breaking Caesar Cipher
- **Only 26 possible keys** - brute force is trivial
- Try all shifts and look for readable text
- Use frequency analysis (E is most common in English)

---

## 1.2 Affine Cipher

### Theory
More secure than Caesar - uses multiplication AND addition.

**Formulas:**
```
Encryption: c = (a × m + b) mod 26
Decryption: m = a^(-1) × (c - b) mod 26

Requirements:
- gcd(a, 26) = 1 (a must be coprime with 26)
- Valid values for a: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
```

### Finding Modular Inverse
To find a^(-1) mod 26, use Extended Euclidean Algorithm or table:

```
a    | 1  3  5  7  9  11 15 17 19 21 23 25
a^-1 | 1  9  21 15 3  19 7  23 11 5  17 25
```

### Example 3: Affine Encryption
**Question:** Encrypt "CAT" with a=5, b=8

**Solution:**
```
C = 2  → (5×2 + 8) mod 26 = 18 mod 26 = 18 → S
A = 0  → (5×0 + 8) mod 26 = 8 mod 26 = 8   → I
T = 19 → (5×19 + 8) mod 26 = 103 mod 26 = 25 → Z

Answer: "SIZ"
```

### Example 4: Affine Decryption
**Question:** Decrypt "SIZ" with a=5, b=8

**Solution:**
```
First find a^(-1): 5^(-1) mod 26 = 21 (from table)

S = 18 → 21 × (18 - 8) mod 26 = 21 × 10 mod 26 = 210 mod 26 = 2 → C
I = 8  → 21 × (8 - 8) mod 26 = 21 × 0 mod 26 = 0 → A
Z = 25 → 21 × (25 - 8) mod 26 = 21 × 17 mod 26 = 357 mod 26 = 19 → T

Answer: "CAT"
```

### Example 5: Known Plaintext Attack
**Question:** You know "HE" encrypts to "KP" with affine cipher. Find a and b.

**Solution:**
```
H = 7, E = 4
K = 10, P = 15

Set up equations:
(a × 7 + b) mod 26 = 10  ... (1)
(a × 4 + b) mod 26 = 15  ... (2)

Subtract (2) from (1):
(a × 7 + b) - (a × 4 + b) mod 26 = 10 - 15 mod 26
3a mod 26 = -5 mod 26 = 21 mod 26

Find a: 3a = 21 mod 26
a = 21 × 3^(-1) mod 26
a = 21 × 9 mod 26 = 189 mod 26 = 7

Find b from equation (1):
7 × 7 + b ≡ 10 (mod 26)
49 + b ≡ 10 (mod 26)
23 + b ≡ 10 (mod 26)
b ≡ -13 ≡ 13 (mod 26)

Answer: a=7, b=13
```

---

## 1.3 Vigenère Cipher

### Theory
Polyalphabetic cipher - uses a keyword to create multiple Caesar shifts.

**Formulas:**
```
Encryption: c_i = (m_i + k_i) mod 26
Decryption: m_i = (c_i - k_i) mod 26

where k_i is the i-th letter of the repeating key
```

### Example 6: Vigenère Encryption
**Question:** Encrypt "ATTACKATDAWN" with key "LEMON"

**Solution:**
```
Plaintext:  A  T  T  A  C  K  A  T  D  A  W  N
Key:        L  E  M  O  N  L  E  M  O  N  L  E
           (repeat key)

A + L = 0 + 11 = 11 → L
T + E = 19 + 4 = 23 → X
T + M = 19 + 12 = 31 mod 26 = 5 → F
A + O = 0 + 14 = 14 → O
C + N = 2 + 13 = 15 → P
K + L = 10 + 11 = 21 → V
A + E = 0 + 4 = 4 → E
T + M = 19 + 12 = 31 mod 26 = 5 → F
D + O = 3 + 14 = 17 → R
A + N = 0 + 13 = 13 → N
W + L = 22 + 11 = 33 mod 26 = 7 → H
N + E = 13 + 4 = 17 → R

Answer: "LXFOPVEFRNHR"
```

### Example 7: Vigenère Decryption
**Question:** Decrypt "LXFOPVEFRNHR" with key "LEMON"

**Solution:**
```
Ciphertext: L  X  F  O  P  V  E  F  R  N  H  R
Key:        L  E  M  O  N  L  E  M  O  N  L  E

L - L = 11 - 11 = 0 → A
X - E = 23 - 4 = 19 → T
F - M = 5 - 12 = -7 mod 26 = 19 → T
O - O = 14 - 14 = 0 → A
P - N = 15 - 13 = 2 → C
V - L = 21 - 11 = 10 → K
E - E = 4 - 4 = 0 → A
F - M = 5 - 12 = -7 mod 26 = 19 → T
R - O = 17 - 14 = 3 → D
N - N = 13 - 13 = 0 → A
H - L = 7 - 11 = -4 mod 26 = 22 → W
R - E = 17 - 4 = 13 → N

Answer: "ATTACKATDAWN"
```

### Breaking Vigenère
1. **Find key length** using:
   - Kasiski examination (look for repeated patterns)
   - Index of Coincidence
2. **Frequency analysis** on each position
3. Try common keys first

---

## 1.4 LFSR (Linear Feedback Shift Register)

### Theory
Used for stream ciphers - generates pseudorandom bit stream.

**Components:**
- Register of n bits
- Feedback polynomial (XOR taps)
- Initial state (seed)

### Example 8: 4-bit LFSR
**Question:** Generate 8 bits from LFSR with:
- Initial state: 1011
- Taps at positions 4 and 3 (polynomial: x^4 + x^3 + 1)

**Solution:**
```
State    | Output | New bit (XOR of taps)
---------|--------|---------------------
1011     | 1      | 1 ⊕ 0 = 1
1101     | 1      | 1 ⊕ 1 = 0
0110     | 0      | 0 ⊕ 1 = 1
1011     | 1      | 1 ⊕ 0 = 1
1101     | 1      | 1 ⊕ 1 = 0
0110     | 0      | 0 ⊕ 1 = 1
1011     | 1      | 1 ⊕ 0 = 1
1101     | 1      | 1 ⊕ 1 = 0

Output sequence: 11011011
```

### Example 9: Stream Cipher with LFSR
**Question:** Encrypt "HI" using LFSR keystream "11010111..."

**Solution:**
```
H = 01001000 (binary)
I = 01001001 (binary)

Keystream: 11010111

H ⊕ keystream:
01001000
⊕ 11010111
----------
10011111 = 0x9F

I ⊕ keystream (next 8 bits):
01001001
⊕ 10101100  (continuing keystream)
----------
11100101 = 0xE5

Ciphertext: 0x9F, 0xE5
```

---

## 1.5 CBC Mode (Cipher Block Chaining)

### Theory
Block cipher mode that XORs each plaintext block with previous ciphertext.

**Encryption:**
```
C_0 = IV (Initialization Vector)
C_i = E_k(P_i ⊕ C_{i-1})
```

**Decryption:**
```
P_i = D_k(C_i) ⊕ C_{i-1}
```

### Example 10: CBC Encryption (Manual)
**Question:** Encrypt two blocks using CBC with simple XOR cipher:
- Plaintext: "ABCD", "EFGH"
- IV = "1234"
- Key = "XXXX"

**Solution:**
```
Block 1:
P1 = "ABCD"
C0 = IV = "1234"
P1 ⊕ C0 = "ABCD" ⊕ "1234" = ...
C1 = Encrypt(P1 ⊕ C0, key)

Block 2:
P2 = "EFGH"
P2 ⊕ C1 = ...
C2 = Encrypt(P2 ⊕ C1, key)
```

### Example 11: CBC Bit Flipping Attack
**Question:** You have ciphertext C with IV. How can you modify the decrypted first block?

**Answer:**
```
Since P_1 = D_k(C_1) ⊕ IV, if you flip bit i in IV:
IV' = IV ⊕ (1 << i)

Then: P_1' = D_k(C_1) ⊕ IV'
           = D_k(C_1) ⊕ IV ⊕ (1 << i)
           = P_1 ⊕ (1 << i)

This flips bit i in the first plaintext block!
```

---

## 🎯 Exam Tips for Classical Ciphers

### Common Mistakes to Avoid
1. **Forgetting modulo 26** in calculations
2. **Wrong inverse** in affine cipher
3. **Not handling negative numbers** correctly (add 26)
4. **Mixing up encryption/decryption** formulas

### Speed Tricks
1. **Memorize** the affine inverse table
2. **Use alphabet strip** for quick conversions
3. **Double-check** wrap-around calculations
4. **Show your work** - partial credit is available

### Practice Problems
Do at least 5 problems of each type:
- [ ] Caesar encryption & decryption
- [ ] Affine cipher with inverse calculation
- [ ] Vigenère with repeating key
- [ ] LFSR state transitions
- [ ] CBC mode with XOR

---

## 📝 Quick Reference Card

```
ALPHABET: A B C D E F G H I J K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
VALUES:   0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25

MODULAR ARITHMETIC:
- Negative: -x mod 26 = 26 - x
- Example: -5 mod 26 = 21

COMMON AFFINE INVERSES:
3^-1 = 9,  5^-1 = 21,  7^-1 = 15
9^-1 = 3,  11^-1 = 19, 15^-1 = 7

XOR PROPERTIES:
- A ⊕ A = 0
- A ⊕ 0 = A
- A ⊕ B ⊕ B = A
```

---

[← Back to Main](../EXAM-PREP-README.md) | [Next: RSA Cryptography →](./02-rsa-cryptography.md)
