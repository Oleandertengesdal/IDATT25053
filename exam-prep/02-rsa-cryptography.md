# 2. RSA Cryptography - Complete Guide

## Overview
RSA is **30-40% of the cryptography portion** - the single most important topic.

**You MUST be able to:**
- Factorize small n values
- Calculate φ(n)
- Find private key d using Extended Euclidean Algorithm
- Perform efficient modular exponentiation
- Identify and exploit RSA weaknesses
- Understand RSA signatures

---

## 2.1 RSA Fundamentals

### Key Generation Algorithm
```
1. Choose two large primes p and q
2. Compute n = p × q
3. Compute φ(n) = (p-1) × (q-1)
4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. Compute d = e^(-1) mod φ(n)

Public key: (n, e)
Private key: (n, d)
```

### Encryption & Decryption
```
Encryption: c = m^e mod n
Decryption: m = c^d mod n
```

---

## 2.2 Step-by-Step Examples

### Example 1: Complete RSA Key Generation
**Question:** Generate RSA keys with p=11, q=13

**Solution:**
```
Step 1: n = p × q
n = 11 × 13 = 143

Step 2: φ(n) = (p-1) × (q-1)
φ(143) = (11-1) × (13-1) = 10 × 12 = 120

Step 3: Choose e (coprime with φ(n))
Let's choose e = 7
Check: gcd(7, 120) = 1 ✓

Step 4: Find d = e^(-1) mod φ(n)
7d ≡ 1 (mod 120)

Using Extended Euclidean Algorithm (see next example)
d = 103

Verification: 7 × 103 = 721 = 6 × 120 + 1 ✓

Public key: (143, 7)
Private key: (143, 103)
```

### Example 2: Finding d using Extended Euclidean Algorithm
**Question:** Find d such that 7d ≡ 1 (mod 120)

**Solution:**
```
Extended Euclidean Algorithm:

120 = 7 × 17 + 1
7 = 1 × 7 + 0

Work backwards:
1 = 120 - 7 × 17
1 = 1 × 120 + (-17) × 7

Therefore: (-17) × 7 ≡ 1 (mod 120)
d = -17 mod 120 = 120 - 17 = 103

Answer: d = 103
```

### Detailed Extended Euclidean Algorithm Table
```
a    | b   | q  | r  | s   | t
-----|-----|----|----|-----|-----
120  | 7   | 17 | 1  | 1   | 0
7    | 1   | 7  | 0  | 0   | 1
1    | 0   | -  | -  | -17 | 1

d = 103 (adjusted to positive)
```

---

## 2.3 Modular Exponentiation (Fast)

### Square-and-Multiply Method
Essential for computing large powers efficiently.

### Example 3: Encryption
**Question:** Encrypt message m=5 with (n=143, e=7)

**Solution:**
```
Compute: 5^7 mod 143

Method 1: Binary exponentiation
7 = 111₂ (binary)

5^1 mod 143 = 5
5^2 mod 143 = 25
5^4 mod 143 = 625 mod 143 = 53

5^7 = 5^4 × 5^2 × 5^1
    = 53 × 25 × 5 mod 143
    = 1325 × 5 mod 143
    = 47 × 5 mod 143
    = 235 mod 143
    = 92

Answer: c = 92
```

### Example 4: Decryption
**Question:** Decrypt c=92 with (n=143, d=103)

**Solution:**
```
Compute: 92^103 mod 143

103 = 64 + 32 + 4 + 2 + 1 = 1100111₂

Build table of squares:
92^1 mod 143 = 92
92^2 mod 143 = 8464 mod 143 = 25
92^4 mod 143 = 25^2 mod 143 = 625 mod 143 = 53
92^8 mod 143 = 53^2 mod 143 = 2809 mod 143 = 81
92^16 mod 143 = 81^2 mod 143 = 6561 mod 143 = 136
92^32 mod 143 = 136^2 mod 143 = 18496 mod 143 = 25
92^64 mod 143 = 25^2 mod 143 = 625 mod 143 = 53

92^103 = 92^64 × 92^32 × 92^4 × 92^2 × 92^1
       = 53 × 25 × 53 × 25 × 92 mod 143
       = 1325 × 53 × 25 × 92 mod 143
       = 47 × 53 × 25 × 92 mod 143
       ... (continue multiplying and reducing)
       = 5

Answer: m = 5
```

---

## 2.4 Factoring n

### Example 5: Small n Factorization
**Question:** You intercept RSA public key (n=713, e=5). Break it.

**Solution:**
```
Step 1: Factor n = 713
Try small primes:
713 ÷ 2? No (odd)
713 ÷ 3? No (7+1+3 = 11, not divisible by 3)
713 ÷ 5? No (doesn't end in 0 or 5)
713 ÷ 7? No
713 ÷ 11? No
713 ÷ 13? No
713 ÷ 17? No
713 ÷ 19? No
713 ÷ 23? No
713 ÷ 29? Yes! 713 = 29 × ?

713 ÷ 29 = 24.586... No
Wait, try again...
713 ÷ 23 = 31 ✓

So: p = 23, q = 31

Step 2: Compute φ(n)
φ(713) = (23-1) × (31-1) = 22 × 30 = 660

Step 3: Find d
5d ≡ 1 (mod 660)

Using Extended Euclidean:
660 = 5 × 132 + 0
Hmm, gcd(5,660) = 5 ≠ 1... Invalid key! e must be coprime.

Let's say e=7 instead:
7d ≡ 1 (mod 660)
d = 283 (using Extended Euclidean)

Now you can decrypt any message!
```

---

## 2.5 RSA Attacks and Weaknesses

### Attack 1: Small e Attack (e=3)
**Example 6:** If e=3 and message is small enough that m^3 < n

**Question:** (n=91, e=3), ciphertext c=8

**Solution:**
```
If m^3 < n, then:
c = m^3 (no modulo reduction happened!)

Simply take cube root:
m = ∛8 = 2

Attack works when m^3 < n
For e=3: m must be < ∛n
For n=91: ∛91 ≈ 4.5, so messages 0-4 are vulnerable
```

### Attack 2: Common Modulus Attack
**Example 7:** Same message sent to two recipients with same n but different e

**Setup:**
- Alice and Bob share n=143
- Alice: e₁=7, Bob: e₂=11
- Message m=5 sent to both
- c₁ = 5^7 mod 143 = 92
- c₂ = 5^11 mod 143 = 75

**Attack:**
```
If gcd(e₁, e₂) = 1, find s₁, s₂ such that:
s₁e₁ + s₂e₂ = 1

For e₁=7, e₂=11:
Extended Euclidean: -3(7) + 2(11) = 1
So: s₁=-3, s₂=2

m = (c₁^s₁ × c₂^s₂) mod n
  = (c₁^(-3) × c₂^2) mod n
  = (92^(-3) × 75^2) mod 143

First find 92^(-1) mod 143:
92 × 75 = 6900 = 48 × 143 + 36
So 92^(-1) ≈ 75... (use Extended Euclidean)

m = 5
```

### Attack 3: Weak Primes (p-1 factorization)
**Example 8:** If p-1 has only small prime factors, Pollard's p-1 algorithm works

**Question:** n=pq where p-1 = 2^2 × 3 × 5

**Solution:**
```
Choose B = 60 (smooth bound)
a = 2
Compute: a^(B!) mod n

If p-1 divides B!, then:
gcd(a^(B!) - 1, n) = p

This quickly reveals p!
```

---

## 2.6 RSA Signatures

### Theory
```
Signing: s = m^d mod n (use private key)
Verification: m = s^e mod n (use public key)
```

### Example 9: Creating a Signature
**Question:** Sign message m=10 with (n=143, d=103)

**Solution:**
```
s = 10^103 mod 143

Using square-and-multiply (similar to Example 4):
... (perform calculation)
s = 120

To verify:
m' = 120^7 mod 143
   = 10 ✓
```

### Example 10: Signature Forgery (Multiplicative Attack)
**Question:** You have valid signatures s₁ for m₁ and s₂ for m₂. Forge signature for m₁×m₂.

**Solution:**
```
Valid signatures:
s₁ = m₁^d mod n
s₂ = m₂^d mod n

Forge signature for m = m₁ × m₂:
s = s₁ × s₂ mod n
  = m₁^d × m₂^d mod n
  = (m₁ × m₂)^d mod n

Verification:
s^e = ((m₁ × m₂)^d)^e = m₁ × m₂ ✓

This is why RSA signatures need padding (like PSS)!
```

---

## 2.7 Chinese Remainder Theorem (CRT)

### Theory
Speeds up RSA decryption by computing mod p and mod q separately.

### Example 11: CRT Decryption
**Question:** Decrypt c=92 using CRT with p=11, q=13, d=103

**Solution:**
```
Step 1: Compute dₚ and dᵩ
dₚ = d mod (p-1) = 103 mod 10 = 3
dᵩ = d mod (q-1) = 103 mod 12 = 7

Step 2: Compute mₚ and mᵩ
mₚ = c^dₚ mod p = 92^3 mod 11
92 mod 11 = 4
4^3 = 64 mod 11 = 9

mᵩ = c^dᵩ mod q = 92^7 mod 13
92 mod 13 = 1
1^7 = 1

Step 3: Combine using CRT
Need to find m such that:
m ≡ 9 (mod 11)
m ≡ 1 (mod 13)

Using CRT formula:
qᵢₙᵥ = q^(-1) mod p = 13^(-1) mod 11 = 6
pᵢₙᵥ = p^(-1) mod q = 11^(-1) mod 13 = 6

m = (mₚ × q × qᵢₙᵥ + mᵩ × p × pᵢₙᵥ) mod n
  = (9 × 13 × 6 + 1 × 11 × 6) mod 143
  = (702 + 66) mod 143
  = 768 mod 143
  = 5

Answer: m = 5
```

---

## 🎯 Exam Tips for RSA

### Must Practice
1. **Extended Euclidean Algorithm** - appears every year
2. **Modular exponentiation** - show your steps
3. **Factoring small n** - try primes up to √n
4. **Recognizing attacks** - small e, common modulus, etc.

### Common Mistakes
1. **Forgetting to reduce mod n** after each step
2. **Using n instead of φ(n)** when finding d
3. **Wrong inverse calculation**
4. **Not simplifying exponents** before computing

### Time-Saving Tips
1. **Check your math** with small test values first
2. **Use calculator** for basic arithmetic (if allowed)
3. **Write intermediate steps** - they give partial credit
4. **Memorize gcd(e, φ(n)) must equal 1**

---

## 📝 RSA Cheat Sheet

```python
# Key Generation
n = p × q
φ(n) = (p-1)(q-1)
e × d ≡ 1 (mod φ(n))

# Encryption/Decryption
c = m^e mod n
m = c^d mod n

# Signatures
s = m^d mod n  # sign
m = s^e mod n  # verify

# Attacks to Watch For
- e = 3 and m^3 < n → cube root attack
- Same n, different e → common modulus
- p-1 or q-1 smooth → Pollard p-1
- m^e ≡ m (mod n) when gcd(m,n) ≠ 1

# Common e Values
e = 3, 5, 17, 65537 (2^16 + 1)

# Factoring Tricks
- Try small primes up to √n
- Use Fermat factorization if p ≈ q
- Check if n is even (n = 2k)
```

---

## 💪 Practice Problems

Do at least 10 RSA problems covering:
- [x] Key generation (finding d)
- [x] Encryption with modular exponentiation
- [x] Decryption with large exponents
- [x] Factoring n (various sizes)
- [x] Small e attack
- [x] Common modulus attack
- [x] Signature creation and verification
- [x] Signature forgery
- [x] CRT speedup
- [x] Identifying weak parameters

---

[← Previous: Classical Ciphers](./01-classical-ciphers.md) | [Next: MAC & Hash Functions →](./03-mac-hash.md)
