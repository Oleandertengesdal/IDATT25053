# IDATT2503 Exam Preparation Guide
## Cybersecurity & Cryptography - Complete Theory & Examples

This guide covers all essential topics for achieving grade A/B on the IDATT2503 exam, based on past exam patterns (2022-2024).

---

## 📚 Table of Contents

### Part 1: Cryptography (~50% of exam)
1. [Classical Ciphers](./exam-prep/01-classical-ciphers.md)
2. [RSA Cryptography](./exam-prep/02-rsa-cryptography.md)
3. [MAC & Hash Functions](./exam-prep/03-mac-hash.md)
4. [Symmetric Ciphers & AES](./exam-prep/04-symmetric-aes.md)

### Part 2: Software Security (~50% of exam)
5. [Buffer Overflow & Binary Exploitation](./exam-prep/05-buffer-overflow.md)
6. [Web Security Vulnerabilities](./exam-prep/06-web-vulnerabilities.md)
7. [Fuzzing & Sanitizers](./exam-prep/07-fuzzing.md)
8. [Penetration Testing Methodology](./exam-prep/08-pentest-methodology.md)
9. [Security Best Practices](./exam-prep/09-security-practices.md)

### Part 3: Practical Exploitation (Bonus Practice)
10. [x86-64 Assembly Basics](./exam-prep/10-assembly-basics.md) 🔧
11. [Exploitation Practice - Vulnerable Programs](./exam-prep/11-exploitation-practice.md) 💻
12. [Create Your Own Vulnerable Programs](./exam-prep/12-create-own-vulns.md) 🛠️
13. [Exam-Critical Topics](./exam-prep/13-exam-critical-topics.md) ⭐⭐⭐ **MUST READ**

### Quick References
- [Exploitation Command Reference](./exam-prep/EXPLOITATION-COMMANDS.md) ⚡
- [Complete Exploitation Summary & Learning Path](./exam-prep/EXPLOITATION-SUMMARY.md) 📋

---

## 🎯 Exam Strategy

### Time Allocation (3-hour exam)
- **Cryptography questions**: 90 minutes
- **Software security questions**: 90 minutes
- **Review**: 30 minutes

### Question Types
1. **Manual calculations** (RSA, classical ciphers) - 40%
2. **Theory explanations** (3-5 sentences) - 30%
3. **Code analysis** (identify vulnerabilities) - 20%
4. **Matching questions** (attacks to examples) - 10%

### High-Yield Topics (appear every year)
- ⭐⭐⭐ RSA calculations (30-40% of crypto)
- ⭐⭐⭐ Classical ciphers (Vigenère, Affine, LFSR)
- ⭐⭐⭐ Buffer overflow & stack layout
- ⭐⭐ Web vulnerabilities (XSS, SQL injection)
- ⭐⭐ Hash functions & MAC
- ⭐ Fuzzing & sanitizers

---

## 📖 How to Use This Guide

### For Comprehensive Study
1. **Week 1-2**: Master cryptography topics (Part 1)
   - Focus heavily on RSA (do 10+ practice problems)
   - Practice manual modular arithmetic
   
2. **Week 3-4**: Master software security (Part 2)
   - Study 2022 Q1 (ROP chains) in detail
   - Practice identifying vulnerabilities in code
   - **Learn assembly basics** (Guide 10) - essential for exploitation
   
3. **Week 5**: Hands-on practice (Part 3)
   - Set up lab environment (GDB, pwntools)
   - Compile and exploit vulnerable programs (Guide 11)
   - Debug exploits to see how they work
   - Practice past exams
   
4. **Final days**: Review formulas and key concepts
   - RSA formulas
   - Hash properties
   - Attack recognition patterns
   - Assembly quick reference

### For Hands-On Practice (Recommended!)
1. **Install tools**: GDB, pwntools, ROPgadget (instructions in Guide 11)
2. **Learn assembly**: Study Guide 10 (registers, instructions, stack)
3. **Exploit programs**: Compile 5 vulnerable programs in Guide 11
4. **Debug with GDB**: See exploits work in real-time
5. **Understand deeply**: Assembly knowledge helps with exam questions

---

## 🔑 Key Formulas to Memorize

### Cryptography
```
RSA:
- n = p × q
- φ(n) = (p-1) × (q-1)
- e × d ≡ 1 (mod φ(n))
- Encrypt: c = m^e mod n
- Decrypt: m = c^d mod n

Affine Cipher:
- Encrypt: c = (a×m + b) mod 26
- Decrypt: m = a^(-1)(c - b) mod 26

Vigenère:
- Encrypt: c_i = (m_i + k_i) mod 26
- Decrypt: m_i = (c_i - k_i) mod 26
```

### Security
- **CIA Triad**: Confidentiality, Integrity, Availability
- **AAA**: Authentication, Authorization, Accounting
- **Defense in Depth**: Multiple layers of security

---

## 📝 Practice Resources

- Past exams: 2022, 2023, 2024
- Exercise sets 1-6
- Lab assignments (especially labs 1-3)
- CryptoHack (for RSA practice)
- PicoCTF (for binary exploitation)

---

Start with [Classical Ciphers →](./exam-prep/01-classical-ciphers.md)
