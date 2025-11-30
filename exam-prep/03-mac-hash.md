# 3. MAC & Hash Functions - Complete Guide

## Overview
Theory-heavy topic that appears in every exam. You must be able to **explain concepts precisely in 3-5 sentences**.

---

## 3.1 Hash Functions

### Definition
A **hash function** H takes arbitrary-length input and produces fixed-length output (digest).

```
H: {0,1}* → {0,1}^n

Example: SHA-256 produces 256-bit output regardless of input size
```

### Three Security Properties

#### 1. Preimage Resistance (One-way)
**Definition:** Given hash h, it should be computationally infeasible to find message m such that H(m) = h.

**Example Answer (exam style):**
"Preimage resistance means that given only a hash value h, an attacker cannot find any input m that produces that hash. This is the one-way property - easy to compute H(m) but hard to reverse. It protects password hashes: even if the hash database is stolen, attackers cannot recover original passwords. Brute force requires ~2^n operations for n-bit hash."

**Practical Example:**
```
Password storage:
User password: "secret123"
Stored hash: 9c2e4d8f3a1b... (SHA-256)

Attacker gets hash but cannot reverse it to find "secret123"
Must try all possible passwords (brute force)
```

#### 2. Second Preimage Resistance
**Definition:** Given message m₁, it should be hard to find different m₂ such that H(m₁) = H(m₂).

**Example Answer (exam style):**
"Second preimage resistance means that given a specific message m₁ and its hash, an attacker cannot find a different message m₂ that produces the same hash value. This prevents an attacker from replacing a legitimate document with a malicious one that has the same hash. It requires ~2^n operations for an n-bit hash. This protects digital signatures: an attacker cannot create a fraudulent document with the same hash as a signed document."

**Practical Example:**
```
Contract m₁: "Pay Bob $100"
Hash: abc123...

Attacker tries to find m₂: "Pay Alice $100000" 
such that H(m₂) = abc123...

Should be computationally infeasible!
```

#### 3. Collision Resistance
**Definition:** It should be hard to find ANY two different messages m₁ ≠ m₂ such that H(m₁) = H(m₂).

**Example Answer (exam style):**
"Collision resistance means it should be computationally infeasible to find any two different messages that hash to the same value. Due to the birthday paradox, this requires ~2^(n/2) operations for an n-bit hash, making it weaker than preimage resistance. Collisions break digital signatures: an attacker could create two documents with the same hash, get one signed, then substitute the other. MD5 and SHA-1 are broken because collision attacks are practical."

**Birthday Paradox:**
```
For n-bit hash:
- Preimage: 2^n operations
- Collision: 2^(n/2) operations (birthday attack)

SHA-256 (256 bits):
- Preimage: 2^256 ≈ impossible
- Collision: 2^128 ≈ still impossible but easier

MD5 (128 bits):
- Collision: 2^64 ≈ feasible with modern computers
```

**Practical Example:**
```
MD5 collision (real attack):
File A: legitimate PDF
File B: malicious PDF
Both have same MD5 hash!

Attacker:
1. Creates File A (looks innocent)
2. Gets it signed
3. Substitutes File B (same hash!)
4. Signature still validates!
```

---

## 3.2 Message Authentication Code (MAC)

### Definition
A **MAC** is a keyed hash function that provides authentication and integrity.

```
MAC: K × M → T
where K = key, M = message, T = tag

Example: HMAC-SHA256(key, message) = tag
```

### MAC vs Hash

**Exam Question Style:** "Explain the difference between a hash function and a MAC."

**Model Answer:**
"A hash function takes only a message as input and produces a digest, providing integrity but not authentication. Anyone can compute the same hash. A MAC requires a secret key in addition to the message, providing both integrity and authentication. Only parties knowing the secret key can generate or verify the MAC tag. Hash functions are public operations, while MACs are authenticated operations requiring key management."

**Comparison Table:**
```
Property          | Hash          | MAC
------------------|---------------|------------------
Input             | Message only  | Key + Message
Authentication    | No            | Yes
Integrity         | Yes           | Yes
Key required      | No            | Yes
Public operation  | Yes           | No
Example           | SHA-256       | HMAC-SHA256
```

### Example 1: Hash vs MAC
**Question:** Why can't we use hash alone for message authentication?

**Answer:**
```
Scenario: Alice sends message m and hash H(m) to Bob

Attack:
1. Eve intercepts m and H(m)
2. Eve modifies m to m'
3. Eve computes H(m') (anyone can!)
4. Eve sends m' and H(m') to Bob
5. Bob verifies H(m') = received hash ✓
6. Bob accepts modified message!

Solution with MAC:
1. Alice sends m and MAC_k(m) using shared key k
2. Eve intercepts and modifies m to m'
3. Eve cannot compute MAC_k(m') without key k
4. Eve's forged MAC won't verify
5. Bob rejects the message
```

---

## 3.3 HMAC (Hash-based MAC)

### Construction
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

where:
- opad = 0x5c repeated (outer padding)
- ipad = 0x36 repeated (inner padding)
- || denotes concatenation
```

### Example 2: HMAC Usage
**Question:** How does HMAC provide authentication?

**Answer:**
```
HMAC-SHA256 with key "secret":

Message: "transfer $100 to Bob"
Tag: HMAC("secret", "transfer $100 to Bob")
    = sha256(("secret"⊕opad) || sha256(("secret"⊕ipad) || message))
    = e3b0c44298fc1c14...

Only someone with key "secret" can:
1. Generate valid tags
2. Verify received tags

Attacker cannot forge tags without the key
```

---

## 3.4 Length Extension Attack

### Vulnerable Hash Functions
MD5, SHA-1, SHA-256 use Merkle-Damgård construction, which is vulnerable.

### Attack Explanation

**Exam Question:** "What is a length extension attack on SHA-256?"

**Model Answer:**
"A length extension attack exploits the Merkle-Damgård construction used by SHA-256. Given H(message) and the length of message (but not message itself), an attacker can compute H(message || padding || extension) without knowing the original message. This breaks naive MAC implementations like MAC = H(key || message) because an attacker can append data and compute a valid MAC. The attack works because the hash function's internal state after processing 'message' becomes the starting state for hashing 'extension'. HMAC prevents this by using two hash operations with different keys."

### Example 3: Length Extension Attack
**Question:** Show length extension attack on MAC = SHA256(key || message)

**Setup:**
```
Key k (unknown to attacker)
Message m = "user=bob"
MAC tag t = SHA256(k || m) = abc123... (known)
```

**Attack:**
```
1. Attacker knows:
   - Message m = "user=bob"
   - Tag t = SHA256(k || m)
   - Length of k (let's say 16 bytes)

2. Attacker constructs:
   - Total input: k || m = 16 + 8 = 24 bytes
   - Padding for 24 bytes: pad₂₄
   - Extension: e = "&admin=true"

3. Attacker computes:
   t' = SHA256_extend(t, e)
   m' = m || pad₂₄ || e
   
4. Now (m', t') is valid!
   SHA256(k || m || pad₂₄ || e) = t'
   
5. Server sees: user=bob[padding]&admin=true
   Attacker gains admin!
```

**Prevention:**
```
❌ Vulnerable: MAC = H(key || message)
✅ Secure: MAC = H(key || H(key || message))  (HMAC style)
✅ Secure: MAC = H(message || key)
✅ Secure: Use HMAC-SHA256 directly
✅ Secure: Use SHA-3 (different construction)
```

---

## 3.5 Practical Applications

### Example 4: Password Storage
**Question:** Why hash passwords with salt?

**Answer:**
```
Without salt:
User A: password "12345" → hash abc123...
User B: password "12345" → hash abc123... (same!)

Attacker sees duplicate hashes:
1. Builds rainbow table for common passwords
2. Cracks all users with same password at once

With salt:
User A: salt₁ = random_16_bytes
        hash = H("12345" || salt₁) = def456...
User B: salt₂ = different_random_16_bytes  
        hash = H("12345" || salt₂) = ghi789...

Now different hashes! Attacker must crack each individually.

Best practice:
hash = Argon2(password, salt, cost)  # Modern KDF
```

### Example 5: Message Integrity
**Question:** Design a protocol for secure file transfer.

**Answer:**
```
Sender (Alice) → Receiver (Bob)
Shared secret key: k

1. Alice computes:
   file_data = read("document.pdf")
   tag = HMAC-SHA256(k, file_data)
   
2. Alice sends:
   (file_data, tag)
   
3. Bob receives and verifies:
   tag' = HMAC-SHA256(k, received_file_data)
   if tag == tag':
       accept file (authenticated & unmodified)
   else:
       reject file (tampered or wrong sender)

This provides:
- Authentication: only someone with key k could create tag
- Integrity: any modification changes tag
- Non-repudiation: Alice cannot deny sending (with k)
```

---

## 3.6 Common Hash Functions

### Comparison
```
Algorithm  | Output | Status        | Speed    | Use Case
-----------|--------|---------------|----------|------------------
MD5        | 128    | ❌ Broken     | Fast     | Never use
SHA-1      | 160    | ❌ Broken     | Fast     | Legacy only
SHA-256    | 256    | ✅ Secure     | Medium   | General purpose
SHA-512    | 512    | ✅ Secure     | Medium   | High security
SHA-3      | Varies | ✅ Secure     | Medium   | Modern choice
BLAKE3     | 256    | ✅ Secure     | Fastest  | New systems
```

### When to Use What

**Exam-style answers:**

**Q: When would you use SHA-256 vs SHA-512?**
```
SHA-256: 
- General purpose applications
- Block chain (Bitcoin uses SHA-256)
- Faster on 32-bit systems
- 128-bit collision resistance sufficient

SHA-512:
- Higher security requirements
- Faster on 64-bit systems
- Digital signatures with long-term validity
- When 256-bit collision resistance needed
```

---

## 🎯 Exam Tips for MAC & Hash

### Common Question Patterns

1. **Define and explain:**
   - Write 3-5 sentences
   - Include technical term, what it means, why it matters
   
2. **Compare two concepts:**
   - State both definitions
   - Explain key difference
   - Give use case for each
   
3. **Attack scenarios:**
   - Describe what attacker knows
   - Show step-by-step attack
   - Explain why it works
   - How to prevent

### Key Points to Remember

```
Hash Properties (ordered by strength):
Collision Resistance (hardest: 2^(n/2))
    ⬇
Second Preimage Resistance (2^n)
    ⬇
Preimage Resistance (easiest: 2^n)

If collision resistance broken → all properties broken
If preimage resistance broken → doesn't affect collision resistance
```

### Common Mistakes
1. **Confusing preimage and second preimage**
2. **Forgetting birthday paradox for collisions**
3. **Not explaining WHY something is secure/insecure**
4. **Mixing up MAC and hash properties**

---

## 📝 Quick Reference

```
DEFINITIONS (memorize):

Hash Function:
"Deterministic function mapping arbitrary-length input to 
fixed-length output with preimage resistance, second preimage
resistance, and collision resistance."

MAC:
"Keyed hash function that provides message authentication
and integrity using a shared secret key."

HMAC:
"Hash-based MAC using two passes with different key derivations
to prevent length extension attacks."

Length Extension:
"Attack on Merkle-Damgård hashes where attacker extends message
without knowing original, breaking naive MAC = H(key||message)."

SECURITY LEVELS (for n-bit hash):
- Preimage: 2^n operations
- Second preimage: 2^n operations  
- Collision: 2^(n/2) operations (birthday)

BROKEN HASHES:
- MD5: Collisions found in seconds
- SHA-1: Collisions found with effort
- SHA-256: Still secure (as of 2024)
```

---

[← Previous: RSA](./02-rsa-cryptography.md) | [Next: Symmetric & AES →](./04-symmetric-aes.md)
