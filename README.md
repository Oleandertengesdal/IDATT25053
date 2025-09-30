# IDATT2503 - Sikkerhet i programvare og kryptografi

[![Security](https://img.shields.io/badge/Security-Software%20%26%20Cryptography-red)](https://github.com/Oleandertengesdal/IDATT25053)
[![NTNU](https://img.shields.io/badge/NTNU-Course-blue)](https://ntnu.no)

This repository contains comprehensive materials for **IDATT2503 - Security in Software and Cryptography** at NTNU. The focus is on practical security concepts, hacking & pentesting, cryptography, and secure software development.

## 📚 Course Overview

This course covers essential topics in software security and cryptography:

- **Cryptography**: Symmetric & asymmetric encryption, block/stream ciphers, hash functions
- **Binary Exploitation**: Buffer overflows, ROP chains, shellcode, format string vulnerabilities
- **Reverse Engineering**: Disassembly, debugging, static and dynamic analysis
- **Fuzzing**: AFL, LibFuzzer, binary fuzzing techniques
- **Web Security**: OWASP Top 10, injection attacks, XSS, CSRF
- **System Programming**: POSIX APIs, secure coding practices
- **Security Tools**: Sanitizers (ASan, MSan, UBSan), static analysis
- **Formal Verification**: Proving software correctness

## 🗂️ Repository Structure

```
.
├── README.md                          # This file
├── resources.md                       # Curated learning resources
├── cheatsheets/                       # Quick reference guides
│   ├── cryptography.md               # Crypto algorithms & concepts
│   ├── fuzzing.md                    # Fuzzing tools & techniques
│   ├── binary-exploitation.md        # Exploitation techniques
│   ├── reverse-engineering.md        # RE tools & methods
│   ├── web-security.md               # Web vulnerabilities & OWASP
│   ├── system-programming.md         # POSIX & secure coding
│   └── sanitizers.md                 # Memory & security sanitizers
└── examples/                          # Practical code examples
    ├── cryptography/                 # Crypto implementations
    ├── fuzzing/                      # Fuzz targets
    ├── binary-exploitation/          # Vulnerable programs
    └── system-programming/           # POSIX examples
```

## 🎯 Quick Start

### Cheatsheets
Each cheatsheet provides concise, practical information on key topics:
- [Cryptography Cheatsheet](cheatsheets/cryptography.md) - Symmetric/asymmetric encryption, hashing
- [Fuzzing Cheatsheet](cheatsheets/fuzzing.md) - AFL, LibFuzzer, fuzzing strategies
- [Binary Exploitation Cheatsheet](cheatsheets/binary-exploitation.md) - BOF, ROP, shellcode
- [Reverse Engineering Cheatsheet](cheatsheets/reverse-engineering.md) - Tools and techniques
- [Web Security Cheatsheet](cheatsheets/web-security.md) - OWASP Top 10, common vulns
- [System Programming Cheatsheet](cheatsheets/system-programming.md) - POSIX, secure coding
- [Sanitizers Cheatsheet](cheatsheets/sanitizers.md) - ASan, MSan, UBSan

### Examples
Practical code examples demonstrating concepts:
- [Cryptography Examples](examples/cryptography/) - Cipher implementations
- [Fuzzing Examples](examples/fuzzing/) - Fuzz targets and harnesses
- [Binary Exploitation Examples](examples/binary-exploitation/) - Vulnerable programs
- [System Programming Examples](examples/system-programming/) - POSIX API usage

### Resources
Check [resources.md](resources.md) for curated learning materials including:
- OWASP resources and projects
- WebGoat, Hacker101, and other CTF platforms
- Books, courses, and tools for security research

## 🛠️ Practical Platforms & Tools

### Hands-On Learning Platforms
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** - Web security training
- **[Hacker101](https://www.hacker101.com/)** - Free security training with CTF
- **[picoCTF](https://picoctf.org/)** - Beginner-friendly CTF platform
- **[OverTheWire](https://overthewire.org/wargames/)** - Wargames for security skills
- **[pwnable.kr](http://pwnable.kr/)** - Binary exploitation challenges

### Essential Security Tools
- **Cryptography**: OpenSSL, GnuPG, CryptoCat
- **Fuzzing**: AFL, AFL++, LibFuzzer, Honggfuzz
- **Binary Analysis**: GDB, radare2, Ghidra, IDA Pro, Binary Ninja
- **Web Security**: Burp Suite, OWASP ZAP, SQLMap
- **Sanitizers**: AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer
- **Static Analysis**: Clang Static Analyzer, Coverity, SonarQube

## 📖 Key Topics

### 1. Cryptography
- **Symmetric Cryptography**: AES, DES, ChaCha20 (block & stream ciphers)
- **Asymmetric Cryptography**: RSA, ECC, Diffie-Hellman
- **Hash Functions**: SHA-256, SHA-3, BLAKE2
- **MACs & Signatures**: HMAC, digital signatures
- **Key Exchange**: Diffie-Hellman, ECDH
- **Cryptographic Protocols**: TLS/SSL, PGP

### 2. Binary Exploitation & Reverse Engineering
- **Buffer Overflows**: Stack, heap, off-by-one
- **Return-Oriented Programming (ROP)**: Gadgets, chain construction
- **Shellcode**: Writing and injecting shellcode
- **Format String Vulnerabilities**: Reading/writing arbitrary memory
- **Disassembly**: x86/x64 assembly, understanding binaries
- **Debugging**: GDB, dynamic analysis techniques
- **Protection Mechanisms**: ASLR, DEP/NX, Stack Canaries, PIE

### 3. Fuzzing
- **Coverage-Guided Fuzzing**: AFL, AFL++, LibFuzzer
- **Binary Fuzzing**: Fuzzing compiled binaries
- **Mutation Strategies**: Bit flipping, dictionary-based fuzzing
- **Corpus Management**: Seed selection, minimization
- **Instrumentation**: Compile-time vs. runtime

### 4. Web Security
- **OWASP Top 10**: Injection, broken auth, XSS, etc.
- **SQL Injection**: Detection and exploitation
- **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based
- **CSRF**: Cross-site request forgery attacks
- **Authentication & Session Management**: Common vulnerabilities
- **Security Headers**: CSP, HSTS, X-Frame-Options

### 5. System Programming & POSIX
- **Secure Coding**: Input validation, bounds checking
- **POSIX APIs**: File operations, process control, IPC
- **Memory Management**: Safe allocation, avoiding leaks
- **Race Conditions**: TOCTOU vulnerabilities
- **Privilege Escalation**: Setuid, capabilities

### 6. Formal Verification
- **Static Analysis**: Abstract interpretation, symbolic execution
- **Model Checking**: Temporal logic, state space exploration
- **Theorem Proving**: Coq, Isabelle/HOL
- **Verification Tools**: KLEE, TLA+, Frama-C

## 🎓 Study Tips

1. **Hands-On Practice**: Use CTF platforms and vulnerable applications
2. **Read Code**: Study both secure and vulnerable implementations
3. **Build Tools**: Implement cryptographic algorithms and exploits
4. **Stay Updated**: Follow security researchers and read advisories
5. **Join Communities**: r/netsec, r/reverseengineering, security Discord servers

## 📝 Contributing

Feel free to contribute additional examples, improve cheatsheets, or add resources. Follow these guidelines:
- Keep examples simple and well-commented
- Test all code before submitting
- Update relevant cheatsheets when adding examples
- Cite sources for techniques and resources

## ⚠️ Ethical Considerations

**Important**: All tools, techniques, and knowledge in this repository should be used ethically and legally:
- Only test systems you own or have explicit permission to test
- Respect privacy and data protection laws
- Use knowledge to improve security, not harm systems
- Follow responsible disclosure for vulnerabilities found

## 📚 Additional Resources

See [resources.md](resources.md) for a comprehensive list of:
- Books and academic papers
- Online courses and tutorials
- Security conferences and talks
- Research blogs and publications
- Community resources

## 🔗 Useful Links

- [OWASP](https://owasp.org/) - Open Web Application Security Project
- [CVE Database](https://cve.mitre.org/) - Common Vulnerabilities and Exposures
- [Exploit-DB](https://www.exploit-db.com/) - Exploit database
- [CWE](https://cwe.mitre.org/) - Common Weakness Enumeration

---

**Course**: IDATT2503 - Sikkerhet i programvare og kryptografi  
**Institution**: NTNU - Norwegian University of Science and Technology
