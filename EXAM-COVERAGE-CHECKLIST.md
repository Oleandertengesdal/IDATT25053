# IDATT2503 Complete Exam Coverage Checklist

## ✅ Verify Complete Coverage of ALL Exam Topics

Use this checklist to ensure you've studied every topic that appears on the exam.

---

## 1. Memory Safety & Binary Exploitation

### 1.1 Stack Basics ✅ COVERED
- [x] **Stack frame layout** (Guide 5, 10)
  - Return address location
  - Saved RBP location  
  - Local variables layout
  - Stack grows DOWN
  
- [x] **Calling convention x86_64** (Guide 10, 13)
  - RDI = 1st argument
  - RSI = 2nd argument
  - RDX = 3rd argument
  - RCX = 4th argument
  - R8 = 5th argument
  - R9 = 6th argument
  - RAX = return value

**Location:** Guide 10 (Section 10.1), Guide 13 (Section 13.3)

### 1.2 Buffer Overflow ✅ COVERED
- [x] **Classic stack buffer overflow** (Guide 5, 11)
- [x] **Dangerous functions** (Guide 13, Section 13.1)
  - gets() - no bounds checking
  - strcpy() - no bounds checking
  - memcpy() - trusts length
  - scanf("%s") - no bounds checking
  - strcat(), sprintf()
  
- [x] **What overflow overwrites** (Guide 5, 10)
  - Local variables first
  - Saved RBP second
  - Return address (main target)

**Location:** Guide 5 (Sections 5.1-5.2), Guide 11 (vuln1.c), Guide 13 (Section 13.1)

### 1.3 Stack Smashing Details ✅ COVERED
- [x] **How stack grows** (DOWN toward lower addresses) - Guide 10
- [x] **Endianness** (little endian) - Guide 5, 10
- [x] **Crafting payload manually** (Guide 5, 11)
  - Calculating offset
  - Packing addresses with p64()
  - Using cyclic patterns

**Location:** Guide 10 (Section 10.3), Guide 11 (Section 11.2)

### 1.4 Exploit Mitigations ✅ COVERED
- [x] **Stack Canary** (Guide 5, 13)
  - Random value before return address
  - Checked before function return
  - Bypass: leak canary, non-sequential overwrite
  
- [x] **ASLR** (Guide 5, 13)
  - Randomizes memory addresses
  - Makes ROP harder
  - Bypass: information leak, brute force (32-bit)
  
- [x] **NX/DEP** (Guide 5, 13)
  - Non-executable stack
  - Blocks shellcode execution
  - Bypass: ROP chains, ret2libc
  
- [x] **PIE** (Guide 5, 13)
  - Program base randomized
  - Makes addresses unknown
  - Bypass: leak code pointer, partial overwrite
  
- [x] **Shadow Stack** (Guide 5, 13)
  - Hardware protected return address copy
  - Blocks ROP attacks
  - Nearly impossible to bypass

**Location:** Guide 5 (Sections 5.3), Guide 13 (Sections 13.9)

### 1.5 Return-Oriented Programming ✅ COVERED
- [x] **What gadgets are** (Guide 5, 10, 11)
  - pop rdi; ret
  - pop rsi; ret
  - Small instruction sequences ending in ret
  
- [x] **Setting registers with gadgets** (Guide 10, 11)
- [x] **Calling functions indirectly** (Guide 11 - vuln3.c)
- [x] **Building ROP chains** (Guide 11)

**Location:** Guide 5 (Section 5.4), Guide 10 (Section 10.5), Guide 11 (Section 11.4)

### 1.6 Shellcode Basics ✅ COVERED
- [x] **Why NX prevents shellcode** (Guide 5, 10)
- [x] **What shellcode is** (Guide 10, 13)
- [x] **Shellcode examples** (Guide 10 - Section 10.6)

**Location:** Guide 10 (Section 10.6)

### 1.7 Assembly Comprehension ✅ COVERED
- [x] **mov, push, pop, call, ret** (Guide 10)
- [x] **Syscalls** (Guide 10, 13)
  - write (1), exit (60), execve (59)
  - RAX = syscall number
  - RDI, RSI, RDX = arguments
  
- [x] **Branches** (Guide 10, 13)
  - cmp, jz, jne, jmp, jg, jl, ja, jb
  
- [x] **Conditionals** (Guide 13 - Section 13.4)
- [x] **What program prints** (Guide 13 - Examples 5, 7, 8)
- [x] **Exit status from registers** (Guide 13 - Examples 6, 7, 8)

**Location:** Guide 10 (Sections 10.2-10.4), Guide 13 (Sections 13.3-13.4, 13.10)

---

## 2. Web Security ✅ COVERED

### 2.1 Cross-Site Scripting (XSS) ✅ COVERED
- [x] **Stored XSS** (Guide 6 - Example 2)
- [x] **Reflected XSS** (Guide 6 - Example 1)
- [x] **DOM XSS** (Guide 6 - Example 3)
- [x] **Impact** (session hijacking, privilege escalation)
- [x] **Multi-level systems** (Blackboard example)

**Location:** Guide 6 (Section 6.1)

### 2.2 Injection Vulnerabilities ✅ COVERED
- [x] **SQL Injection** (Guide 6)
  - ' OR 1=1 --
  - sleep(10) time-based
  - Prepared statements defense
  - Examples 4, 5, 6, 7
  
- [x] **Command Injection** (Guide 6)
  - system("ping " + input)
  - Payloads: "; id #, || id, backticks
  - Prevention methods
  - Examples 8, 9, 10
  
- [x] **Server-Side Template Injection (SSTI)** (Guide 6)
  - {{ 2+2 }}
  - Jinja2, Twig frameworks
  - Leads to RCE
  - Examples 13, 14
  
- [x] **Server-Side Request Forgery (SSRF)** (Guide 6)
  - Unescaped URLs
  - http://127.0.0.1
  - http://169.254.169.254 (AWS metadata)
  - Examples 11, 12

**Location:** Guide 6 (Sections 6.2-6.5)

### 2.3 CSRF ✅ COVERED
- [x] **Requires logged-in user** (Guide 6)
- [x] **Defenses: CSRF tokens, SameSite** (Guide 6)
- [x] **Example 15**

**Location:** Guide 6 (Section 6.6)

### 2.4 Input Sanitization ✅ COVERED
- [x] **Blacklists vs whitelists** (Guide 9)
- [x] **Escaping** (HTML, JS, SQL, shell) - Guide 6
- [x] **Regex pitfalls** (dot not escaped → SSRF)

**Location:** Guide 6 (all sections), Guide 9 (Section 9.5)

### 2.5 HTTP ✅ COVERED
- [x] **HTTP 302 redirect** (Guide 6)
- [x] **Cookies (Set-Cookie)** (Guide 6, 9)
- [x] **Headers in attacks** (Guide 6)
- [x] **SameSite policy** (Guide 6, 9)

**Location:** Guide 6, Guide 9 (Section 9.6)

### 2.6 Server Privilege ✅ COVERED
- [x] **NEVER run server as root** (Guide 9, 13)
- [x] **Principle of least privilege** (Guide 9, 13)
- [x] **Root → full compromise** (Guide 13 - Section 13.7)

**Location:** Guide 9 (Section 9.1), Guide 13 (Section 13.7)

---

## 3. Fuzzing & Bug-finding ✅ COVERED

### 3.1 What Fuzzers Do ✅ COVERED
- [x] **Random/semi-random inputs** (Guide 7)
- [x] **Guided fuzzing (coverage-based)** (Guide 7 - Section 7.2)
- [x] **Crashes vs undefined behavior** (Guide 7)

**Location:** Guide 7 (Sections 7.1-7.2)

### 3.2 Undefined Behavior Sanitizer ✅ COVERED
- [x] **UBSan detects:**
  - Integer overflow (Guide 7 - Example 5, Guide 13)
  - Divide by zero (Guide 7, 13)
  - Buffer overflows (with ASan)
  - Use-after-free (with ASan)
  
- [x] **Exam examples:**
  - Average function dividing by length → divide by zero
  - Integer overflow on sum
  - Array indexing errors

**Location:** Guide 7 (Sections 7.3-7.4), Guide 13 (Section 13.10)

### 3.3 LibFuzzer ✅ COVERED
- [x] **How inputs passed** (Guide 7 - Example 8)
- [x] **Debugger breaks with input** (Guide 7)
- [x] **How fuzzers learn code paths** (Guide 7 - Section 7.2)

**Location:** Guide 7 (Sections 7.5)

---

## 4. System Security Concepts ✅ COVERED

### 4.1 Least Privilege ✅ COVERED
- [x] **Running as root vs normal user** (Guide 9, 13)
- [x] **Linux capabilities** (Guide 13)
- [x] **Separation of privilege** (Guide 9, 13)

**Location:** Guide 9 (Section 9.1), Guide 13 (Section 13.7)

### 4.2 Memory and Password Safety ✅ COVERED
- [x] **Storing passwords in memory** (Guide 9, 13)
- [x] **Clearing memory** (volatile, overwriting) - Guide 13
  - explicit_bzero()
  - volatile keyword
  - Why memset() can be optimized away
  
- [x] **Why C/C++ unsafe by default** (Guide 13)
- [x] **Why Rust safe by design** (Guide 13)

**Location:** Guide 9 (Section 9.3), Guide 13 (Sections 13.5, 13.6)

---

## 5. Rust Safety & Comparison ✅ COVERED

### 5.1 What Rust Prevents ✅ COVERED
- [x] **Buffer overflow** (Guide 13 - Example 11)
- [x] **Use-after-free** (Guide 13 - Example 12)
- [x] **Double free** (Guide 13)
- [x] **Data races** (Guide 13 - Example 10)

**Location:** Guide 13 (Section 13.5)

### 5.2 Rust Concepts ✅ COVERED
- [x] **Ownership** (Guide 13 - Example 9)
- [x] **Borrow checker** (Guide 13 - Example 10)
- [x] **Safe vs unsafe Rust** (Guide 13)
- [x] **System programming language** (Guide 13)

**Location:** Guide 13 (Section 13.5)

---

## 6. System Programming Basics ✅ COVERED

### 6.1 System Calls ✅ COVERED
- [x] **Write syscall (1)** (Guide 10, 13 - Example 5)
- [x] **Exit syscall (60)** (Guide 10, 13 - Examples 6, 7, 8)
- [x] **Execve syscall (59)** (Guide 10)
- [x] **Registers in x86_64:**
  - RAX = syscall number
  - RDI, RSI, RDX = arguments

**Location:** Guide 10 (Section 10.6), Guide 13 (Section 13.3)

### 6.2 Understanding Programs ✅ COVERED
- [x] **What assembly prints** (Guide 13 - Examples 5, 7)
- [x] **Exit status** (Guide 13 - Examples 6, 7, 8)
- [x] **Understanding mov, jnz/jz, dec** (Guide 10, 13)

**Location:** Guide 10 (Section 10.2), Guide 13 (Sections 13.3-13.4, 13.10)

### 6.3 Memory Layout ✅ COVERED
- [x] **Stack** (local vars, return addresses)
- [x] **Heap** (malloc)
- [x] **Global/static data** (Data segment)
- [x] **Code section** (Text segment)
- [x] **Where string literals live** (Text segment)

**Location:** Guide 10 (Section 10.3), Guide 13 (Section 13.2)

---

## 7. Penetration Testing ✅ COVERED

### 7.1 Methodology ✅ COVERED
- [x] **Correct order:**
  1. Agreement phase
  2. Planning & Reconnaissance
  3. Scanning / Enumeration
  4. Exploitation
  5. Maintaining access
  6. Evidence collection & Reporting

**Location:** Guide 8 (All sections)

### 7.2 Each Stage ✅ COVERED
- [x] **Active/passive recon** (Guide 8 - Section 8.3)
- [x] **Port scans** (Guide 8 - Section 8.4)
- [x] **Vulnerability scans** (Guide 8 - Section 8.4)
- [x] **Exploit creation** (Guide 8 - Section 8.5)
- [x] **Privilege escalation** (Guide 8 - Section 8.6)
- [x] **Cleanup and reporting** (Guide 8 - Section 8.7)

**Location:** Guide 8 (Complete)

---

## 8. Attack Identification ✅ COVERED

### 8.1 Payload Matching ✅ COVERED
- [x] **SQL Injection:** ' OR 1=1 --
- [x] **Time-based SQLi:** ' OR sleep(10); --
- [x] **Command Injection:** `; whoami`, backticks, ||
- [x] **SSTI:** {{ 2 + 2 }}, {{ 7*7 }}
- [x] **XSS:** <script>alert(1)</script>, onerror=
- [x] **SSRF:** http://0.0.0.0:8081, http://169.254.169.254
- [x] **Format string:** %p, %x, %s, %n
- [x] **Path traversal:** ../../../etc/passwd

**Location:** Guide 6 (All examples), Guide 13 (Section 13.8 - COMPLETE TABLE)

### 8.2 Exam Patterns ✅ COVERED
- [x] **Match attack to payload** (Guide 13 - Example 16)
- [x] **Match vulnerability to code snippet** (Guide 6, 13)

**Location:** Guide 13 (Section 13.8)

---

## 9. Miscellaneous Testable Concepts ✅ COVERED

- [x] **What is shellcode?** (Guide 10, 13)
- [x] **What is NX bit?** (Guide 5, 13)
- [x] **Why is ASLR useful?** (Guide 5, 13)
- [x] **Why is fast password hashing bad?** (Guide 3)
- [x] **Why code injection possible in C not Rust?** (Guide 13)
- [x] **Why unsafe languages dangerous in servers?** (Guide 9, 13)

**Location:** Guides 3, 5, 9, 10, 13

---

## 📊 Coverage Summary

### Total Topics Required: 60+
### Topics Covered: ✅ 60+ (100%)

**New Guide 13 fills ALL gaps:**
- ✅ Dangerous C functions (gets, strcpy, scanf)
- ✅ Memory layout (where string literals live)
- ✅ Syscalls (write, exit, examples)
- ✅ Assembly branches (cmp, jz, jg, etc.)
- ✅ Rust safety (ownership, borrow checker)
- ✅ Password memory safety (volatile, explicit_bzero)
- ✅ Running as root (privilege separation)
- ✅ Attack payload matching (complete table)
- ✅ Protection summary table
- ✅ Common exam code patterns

---

## 🎯 Priority Reading Order

### Must Read Before Exam:
1. **Guide 13** - Exam-Critical Topics ⭐⭐⭐ (NEW - 2 hours)
2. **Guide 5** - Buffer Overflow (2 hours)
3. **Guide 10** - Assembly Basics (2 hours)
4. **Guide 6** - Web Vulnerabilities (2 hours)
5. **Guide 2** - RSA (3 hours)

### Practice:
6. **Guide 11** - Vulnerable Programs (4 hours hands-on)
7. **Guide 7** - Fuzzing (1 hour)

### Final Review:
8. **Guide 13** - Section 13.8 (payload matching)
9. **Guide 13** - Section 13.10 (common patterns)
10. Quick reference sections of all guides

---

## 📋 Final Exam Checklist

**Day Before Exam:**
- [ ] Review Guide 13 completely
- [ ] Review payload matching table (13.8)
- [ ] Review protection mechanisms table (13.9)
- [ ] Review dangerous functions (13.1)
- [ ] Review syscall table (13.3)
- [ ] Review Rust safety (13.5)
- [ ] Review assembly examples (13.3-13.4, 13.10)
- [ ] Review calling convention (RDI, RSI, RDX...)
- [ ] Quick skim of web vulnerabilities (Guide 6)
- [ ] Quick skim of ROP chains (Guide 5.4, 10.5)

**You are now 100% prepared! 🎓**
