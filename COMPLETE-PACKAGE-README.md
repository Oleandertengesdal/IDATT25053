# 🎯 Complete IDATT2503 Exploitation & Hacking Package

## What's Included

Your complete exam prep package now includes **13 comprehensive guides** covering both theory and hands-on exploitation skills.

---

## 📚 Complete Guide List

### Core Theory (Guides 1-9) - For Exam
1. **Classical Ciphers** - Caesar, Affine, Vigenère, LFSR, CBC (11 examples)
2. **RSA Cryptography** ⭐ - Key generation, attacks, signatures (11 examples)
3. **MAC & Hash** - HMAC, length extension, birthday paradox
4. **Symmetric AES** - Modes, confusion/diffusion, key management
5. **Buffer Overflow** ⭐⭐⭐ - Stack layout, ROP, protections
6. **Web Vulnerabilities** ⭐ - XSS, SQLi, SSRF, SSTI, CSRF (18 examples)
7. **Fuzzing** - Coverage-guided, sanitizers, UB detection
8. **Pentest Methodology** - 6 phases, tools, techniques
9. **Security Practices** - Least privilege, defense in depth, MFA

### Exploitation Skills (Guides 10-12) - Hands-On Practice
10. **x86-64 Assembly** 🔧 - Registers, instructions, stack, ROP gadgets
11. **Vulnerable Programs** 💻 - 5 complete programs + exploits + GDB
12. **Create Your Own** 🛠️ - Build custom vulnerable programs

### Quick References
- **Command Reference** ⚡ - GDB, pwntools, ROPgadget commands
- **Complete Summary** 📋 - Learning path, exercises, checklist

**Total:** 80+ worked examples, 5 vulnerable programs, complete exploitation toolkit

---

## 🚀 Quick Start Guide

### Option 1: Theory Only (Exam Focus)
If you just want to pass the exam with good understanding:

1. Read Guides 1-9 (theory)
2. Work through numbered examples
3. Review quick reference sections
4. Practice past exam questions

**Time needed:** 20-30 hours

---

### Option 2: Full Package (Theory + Practice)
If you want to actually become good at exploitation:

#### Week 1: Setup & Assembly (5 hours)
```bash
# Install tools
sudo apt install build-essential gdb python3 python3-pip
pip3 install pwntools ROPgadget
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Disable ASLR for practice
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

**Study:**
- Read Guide 10 (Assembly Basics)
- Learn registers: RAX, RDI, RSI, RBP, RSP, RIP
- Understand instructions: mov, push, pop, call, ret
- Practice reading disassembly

#### Week 2: Basic Exploitation (8 hours)
**Program:** vuln1.c (Basic Stack Overflow)

```bash
# Copy code from Guide 11
gcc -fno-stack-protector -z execstack -no-pie vuln1.c -o vuln1

# Test
./vuln1 "Hello"
./vuln1 "$(python3 -c 'print("A"*100)')"  # Crash!

# Find offset in GDB
gdb ./vuln1
(gdb) run $(python3 -c 'from pwn import *; print(cyclic(200))')
(gdb) cyclic -l <crash_address>

# Write exploit
python3 exploit1.py  # From Guide 11
```

**Skills learned:**
- Stack layout visualization
- Offset calculation
- Basic pwntools usage
- GDB debugging

#### Week 3: ROP Chains (10 hours)
**Program:** vuln3.c (ROP Challenge)

```bash
# Compile with NX
gcc -fno-stack-protector -no-pie vuln3.c -o vuln3

# Find gadgets
ROPgadget --binary ./vuln3 | grep "pop rdi"

# Build ROP chain (Guide 11)
python3 exploit3.py
```

**Skills learned:**
- Finding ROP gadgets
- Building exploit chains
- Bypassing NX protection
- Understanding calling conventions

#### Week 4: Advanced Techniques (12 hours)
**Programs:** vuln2.c, vuln4.c, vuln5.c

- Format string exploitation
- Integer overflow
- Use-after-free
- Creating own vulnerabilities (Guide 12)

#### Week 5: Theory + Past Exams (15 hours)
- Review Guides 1-9 (theory)
- RSA calculations (many practice problems)
- Web vulnerability recognition
- Past exam questions

**Total time:** 50 hours to mastery

---

## 📖 Learning by Topic

### "I want to understand buffer overflows"
**Path:**
1. Guide 5 (Buffer Overflow theory)
2. Guide 10 (Assembly - stack section)
3. Guide 11 (vuln1.c - practice)
4. Guide 12 (create variations)

### "I want to learn ROP chains"
**Path:**
1. Guide 10 (Assembly - ROP gadgets section)
2. Guide 5 (ROP theory)
3. Guide 11 (vuln3.c - ROP practice)
4. Command Reference (ROPgadget)

### "I want to use GDB effectively"
**Path:**
1. Guide 11 (Debugging section)
2. Command Reference (GDB commands)
3. Practice with any vulnerable program

### "I want to understand assembly"
**Path:**
1. Guide 10 (complete read)
2. Practice: `objdump -d /bin/ls | less`
3. Guide 11 (read disassembly in GDB)
4. Create simple C programs, disassemble them

---

## 💻 The 5 Practice Programs

### vuln1.c - Baby's First Exploit
- **Difficulty:** ⭐ Easy
- **Protections:** None
- **Goal:** Call win() function
- **Skills:** Offset calculation, basic overflow
- **Time:** 30 minutes

### vuln2.c - Format String
- **Difficulty:** ⭐⭐ Medium
- **Protections:** PIE disabled
- **Goal:** Leak secret from memory
- **Skills:** Format string exploitation
- **Time:** 1 hour

### vuln3.c - ROP Chain
- **Difficulty:** ⭐⭐⭐ Hard
- **Protections:** NX enabled
- **Goal:** system("/bin/sh") via ROP
- **Skills:** Gadget finding, chain building
- **Time:** 2-3 hours

### vuln4.c - Integer Overflow
- **Difficulty:** ⭐⭐ Medium
- **Protections:** Canary
- **Goal:** Bypass size check
- **Skills:** Integer wrap, type confusion
- **Time:** 1 hour

### vuln5.c - Use-After-Free
- **Difficulty:** ⭐⭐⭐ Hard
- **Protections:** None
- **Goal:** Hijack function pointer
- **Skills:** Heap exploitation, UAF
- **Time:** 2 hours

---

## 🎯 Skills Checklist

### Assembly (Guide 10)
- [ ] Know all register names and purposes
- [ ] Can read mov, push, pop, call, ret
- [ ] Understand stack frame layout
- [ ] Can identify function prologue/epilogue
- [ ] Know calling convention (args in RDI, RSI, RDX)
- [ ] Can spot buffer on stack (RBP-offset)
- [ ] Can calculate distance to return address
- [ ] Understand what ROP gadgets are

### Exploitation (Guide 11)
- [ ] Successfully exploited vuln1.c
- [ ] Can find offset using cyclic pattern
- [ ] Can write basic pwntools script
- [ ] Can debug exploit in GDB
- [ ] Understand format string basics
- [ ] Built working ROP chain
- [ ] Know how to find gadgets
- [ ] Exploited at least 3 different vulnerability types

### Tools (Command Reference)
- [ ] Can use pwntools (ELF, process, p64)
- [ ] Can use GDB (breakpoints, x/20x, disassemble)
- [ ] Can use ROPgadget (--binary, --only)
- [ ] Know compilation flags (checksec, gcc flags)
- [ ] Can generate patterns (cyclic)
- [ ] Can read disassembly (objdump -d)

### Theory (Guides 1-9)
- [ ] Can calculate RSA (keygen, encrypt, decrypt)
- [ ] Know classical ciphers (Caesar, Vigenère)
- [ ] Understand hash properties
- [ ] Know web vulnerabilities (XSS, SQLi, etc.)
- [ ] Understand protections (canary, NX, ASLR, PIE)
- [ ] Know pentest phases
- [ ] Understand security principles

---

## 📊 Exam Coverage

### Cryptography (50%)
- **High Yield:** RSA (30-40% of crypto section)
- Classical ciphers, hash functions, AES modes
- **Preparation:** Guides 1-4, many practice calculations

### Software Security (50%)
- **Very Common:** Buffer overflow (2022 Q1 on ROP!)
- **Common:** Web vulnerabilities (matching questions)
- Fuzzing, pentest methodology, best practices
- **Preparation:** Guides 5-9 + practical skills 10-12

---

## 🔥 Priority Study Order

### For A/B Grade (Minimum)
**Must Master (40 hours):**
1. RSA calculations (Guide 2) - 10 hours
2. Buffer overflow (Guides 5, 10, 11) - 15 hours
3. Web vulnerabilities (Guide 6) - 5 hours
4. Classical ciphers (Guide 1) - 5 hours
5. Past exams - 5 hours

### For Deep Understanding (50 hours)
**Add:**
6. All 5 vulnerable programs (Guide 11) - 8 hours
7. Assembly mastery (Guide 10) - 2 hours

### For Mastery (70+ hours)
**Add:**
8. Create own vulnerabilities (Guide 12) - 10 hours
9. All theory guides in depth - 10+ hours

---

## 💡 Pro Tips

### Studying Theory
- Work through examples with pen and paper
- Don't just read - actually calculate RSA problems
- Draw stack layouts when studying buffer overflows
- Create flashcards for formulas

### Practicing Exploitation
- Always verify in GDB first
- Use cyclic patterns, don't guess offsets
- Start with all protections disabled
- Add one protection at a time
- Read error messages carefully

### Using Tools
- pwntools documentation is excellent
- pwndbg makes GDB 100x better
- ROPgadget can find any gadget
- Practice == speed == confidence

### Day Before Exam
- Review quick reference sections only
- Review formula sheet (Guide README)
- Review attack recognition patterns
- Sleep well!

---

## 📁 File Structure

```
exam-prep/
├── 01-classical-ciphers.md          # Caesar, Vigenère, LFSR
├── 02-rsa-cryptography.md           # RSA theory + attacks
├── 03-mac-hash.md                   # HMAC, length extension
├── 04-symmetric-aes.md              # AES modes, key mgmt
├── 05-buffer-overflow.md            # Stack, ROP, protections
├── 06-web-vulnerabilities.md        # XSS, SQLi, SSRF, etc.
├── 07-fuzzing.md                    # Coverage, sanitizers
├── 08-pentest-methodology.md        # 6 phases, tools
├── 09-security-practices.md         # Principles, best practices
├── 10-assembly-basics.md            # 🔧 x86-64 assembly
├── 11-exploitation-practice.md      # 💻 5 vulnerable programs
├── 12-create-own-vulns.md           # 🛠️ Build your own
├── EXPLOITATION-COMMANDS.md         # ⚡ Quick command ref
└── EXPLOITATION-SUMMARY.md          # 📋 This file
```

---

## 🎓 Ready to Start?

### Absolute Beginner Path
```
Day 1-2:   Read Guide 10 (Assembly)
Day 3-5:   Exploit vuln1.c (Guide 11)
Day 6-7:   Read Guide 5 (Buffer Overflow theory)
Day 8-10:  Exploit vuln3.c (ROP)
Day 11-15: Theory guides 1-4, 6-9
Day 16-20: Past exams
```

### Experienced Path
```
Day 1:     All 5 programs (Guide 11)
Day 2-3:   Create own challenges (Guide 12)
Day 4-7:   Theory review (Guides 1-9)
Day 8-10:  Past exams, weak areas
```

---

## 🚀 Start NOW

**Right this second:**
```bash
mkdir ~/idatt2503-practice
cd ~/idatt2503-practice
pip3 install pwntools
```

**Then copy vuln1.c from Guide 11 and:**
```bash
gcc -fno-stack-protector -z execstack -no-pie vuln1.c -o vuln1
./vuln1 "$(python3 -c 'print("A"*100)')"
```

**Segfault? Perfect. You're ready to learn! 🎉**

---

## 📞 Need Help?

- **Stuck on assembly?** → Read Guide 10 examples again
- **Exploit not working?** → Debug in GDB (Guide 11)
- **Can't find gadgets?** → Check Command Reference
- **Confused about theory?** → Each guide has Quick Reference

---

**Good luck! Now go hack some programs! 💪🔥**

[← Back to Main](../EXAM-PREP-README.md)
