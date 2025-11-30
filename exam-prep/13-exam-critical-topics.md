# 13. Exam-Critical Topics - Complete Coverage

## Overview
This guide covers **ALL remaining exam topics** that appear consistently but weren't fully covered elsewhere. These are **GUARANTEED** exam questions.

---

## 13.1 Dangerous C Functions (Always on Exam)

### Functions You MUST Know Are Vulnerable

**Exam Pattern:** "Which function is vulnerable to buffer overflow?"

| Function | Why Dangerous | Safe Alternative |
|----------|---------------|------------------|
| `gets()` | No bounds checking, reads until newline | `fgets()` |
| `strcpy()` | No bounds checking | `strncpy()` or `strlcpy()` |
| `strcat()` | No bounds checking | `strncat()` or `strlcat()` |
| `sprintf()` | No bounds checking | `snprintf()` |
| `scanf("%s")` | No bounds checking | `scanf("%50s")` with width |
| `memcpy()` | Trusts length parameter | Check bounds first |

### Example 1: gets() Vulnerability

```c
// VULNERABLE - Always exploitable
char buffer[64];
gets(buffer);  // Reads unlimited input!

// Input: "A" * 100
// Result: Buffer overflow, return address overwritten
```

**Why it's tested:**
- Appears in 2022, 2023, 2024 exams
- Classic vulnerability
- Easy to recognize in code

### Example 2: strcpy() Vulnerability

```c
void vulnerable(char *user_input) {
    char buffer[32];
    strcpy(buffer, user_input);  // No length check!
}

// If user_input > 32 bytes → overflow
```

**Safe version:**
```c
void safe(char *user_input) {
    char buffer[32];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
}
```

### Example 3: scanf() Without Width

```c
// VULNERABLE
char name[20];
scanf("%s", name);  // Can overflow!

// SAFE
char name[20];
scanf("%19s", name);  // Max 19 chars + null byte
```

**Exam Question:** "Why is `scanf("%s")` dangerous?"

**Answer:** "`scanf("%s")` reads input until whitespace without bounds checking, allowing buffer overflow. An attacker can provide input longer than the destination buffer, overwriting adjacent memory including the return address. The format specifier should include a width limiter (e.g., `%19s` for a 20-byte buffer) to prevent reading beyond buffer size. Using `scanf()` without width specification is equivalent to `gets()` in vulnerability."

---

## 13.2 Memory Layout (System Programming)

### Complete Memory Layout

**Exam Question:** "Where do string literals live in memory?"

```
High addresses (0xFFFFFFFF...)
│
├─── Kernel space (not accessible)
│
├─── Stack                    ← Local variables, grows DOWN
│    - Function call frames
│    - Return addresses
│    - Local variables
│    - Function arguments
│
├─── Memory-mapped region     ← Shared libraries
│    - libc.so
│    - Other .so files
│
├─── Heap                     ← malloc(), grows UP
│    - Dynamic allocations
│    - Objects
│
├─── BSS segment              ← Uninitialized global/static
│    - int global;
│
├─── Data segment             ← Initialized global/static
│    - int global = 10;
│
├─── Text/Code segment        ← Read-only, executable
│    - Program instructions
│    - String literals ← ANSWER: HERE!
│    - Constants
│
Low addresses (0x00000000...)
```

### Example 4: What Lives Where

```c
#include <stdio.h>
#include <stdlib.h>

int global_initialized = 42;     // Data segment
int global_uninitialized;        // BSS segment
const char *str = "Hello";       // "Hello" in text segment

void function() {
    int local = 10;              // Stack
    static int static_var = 20;  // Data segment
    char *heap = malloc(100);    // Heap
    char buffer[64];             // Stack
}
```

**Exam Question:** "Where is the string 'Hello' stored?"

**Answer:** "Text/code segment (read-only)"

---

## 13.3 Syscalls (Assembly & System Programming)

### Linux x86-64 Syscall Convention

**Critical for exam:**

```assembly
; Syscall numbers in RAX
; Arguments in: RDI, RSI, RDX, R10, R8, R9
; Return value in RAX
; Invoke with: syscall instruction
```

### Common Syscalls

| Number | Name | Arguments | Purpose |
|--------|------|-----------|---------|
| 0 | read | (fd, buf, count) | Read from file |
| 1 | write | (fd, buf, count) | Write to file |
| 2 | open | (filename, flags) | Open file |
| 3 | close | (fd) | Close file |
| 60 | exit | (status) | Exit program |
| 59 | execve | (filename, argv, envp) | Execute program |

### Example 5: Write Syscall

```assembly
; Write "Hello\n" to stdout
section .data
    msg db "Hello", 0xa    ; 0xa = newline
    len equ $ - msg

section .text
global _start
_start:
    mov rax, 1             ; syscall number for write
    mov rdi, 1             ; fd = 1 (stdout)
    mov rsi, msg           ; buffer address
    mov rdx, len           ; count = 6 bytes
    syscall                ; invoke kernel

    mov rax, 60            ; syscall number for exit
    mov rdi, 0             ; exit code = 0
    syscall
```

**Exam Question:** "What does this assembly print?"

**Answer:** "Hello" (with newline)

**Exam Question:** "What is the exit status?"

**Answer:** "0" (from RDI before exit syscall)

### Example 6: Reading Assembly for Exit Code

```assembly
mov rdi, 42
mov rax, 60
syscall
```

**Question:** "What is the exit code?"

**Answer:** 42

```assembly
mov rax, 5
add rax, 3
mov rdi, rax
mov rax, 60
syscall
```

**Question:** "What is the exit code?"

**Answer:** 8 (5 + 3)

---

## 13.4 Assembly Branches & Conditionals

### Jump Instructions (Exam Critical!)

**After `cmp a, b`:**

| Instruction | Meaning | When it jumps |
|-------------|---------|---------------|
| `je` | Jump if Equal | a == b |
| `jne` | Jump if Not Equal | a != b |
| `jz` | Jump if Zero | result == 0 |
| `jnz` | Jump if Not Zero | result != 0 |
| `jg` | Jump if Greater (signed) | a > b |
| `jl` | Jump if Less (signed) | a < b |
| `jge` | Jump if Greater or Equal | a >= b |
| `jle` | Jump if Less or Equal | a <= b |
| `ja` | Jump if Above (unsigned) | a > b |
| `jb` | Jump if Below (unsigned) | a < b |

### Example 7: Conditional Logic

```assembly
mov rax, 10
cmp rax, 5
jg greater        ; Jump if 10 > 5 (TRUE, jumps)
mov rbx, 1
jmp done
greater:
    mov rbx, 2    ; Executes this
done:
    mov rdi, rbx  ; RDI = 2
    mov rax, 60
    syscall
```

**Question:** "What is the exit code?"

**Answer:** 2

### Example 8: Loop Understanding

```assembly
mov rcx, 5        ; Counter
loop_start:
    dec rcx       ; rcx--
    jnz loop_start ; Jump if rcx != 0

mov rdi, rcx      ; rcx = 0 now
mov rax, 60
syscall
```

**Question:** "What is the exit code?"

**Answer:** 0

**Question:** "How many times does the loop execute?"

**Answer:** 5 times

---

## 13.5 Rust Memory Safety (GUARANTEED EXAM TOPIC)

### Why Rust Prevents Common Bugs

**Exam Question (2023):** "Why is Rust considered memory-safe?"

**Model Answer:**
"Rust achieves memory safety through its ownership system and borrow checker enforced at compile time. Each value has exactly one owner, and ownership can be transferred or borrowed immutably (multiple readers) or mutably (one writer). This prevents: (1) use-after-free by invalidating references when ownership moves; (2) double-free by ensuring only one owner can free memory; (3) buffer overflows through bounds checking on array access; (4) data races by preventing concurrent mutable access. Unlike C where these are runtime errors or undefined behavior, Rust catches violations at compile time with zero runtime overhead. The `unsafe` keyword explicitly marks code that bypasses these checks."

### Example 9: Ownership

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = s1;              // Ownership moved to s2
    // println!("{}", s1);    // ERROR: s1 no longer valid
    println!("{}", s2);       // OK
}
```

**Why safe:** Can't use s1 after move → prevents use-after-free

### Example 10: Borrowing

```rust
fn main() {
    let mut s = String::from("hello");
    
    let r1 = &s;         // Immutable borrow
    let r2 = &s;         // Multiple immutable borrows OK
    println!("{} {}", r1, r2);
    
    // let r3 = &mut s;  // ERROR: Can't mutably borrow while immutable refs exist
}
```

**Why safe:** Prevents data races at compile time

### Example 11: Array Bounds

```c
// C - Undefined behavior
int arr[5];
arr[10] = 42;  // Compiles! Crashes or corrupts memory at runtime
```

```rust
// Rust - Safe
let arr = [0; 5];
arr[10] = 42;  // Compile error if index is constant
                // Runtime panic if index is variable (safe crash)
```

### Example 12: No Use-After-Free

```c
// C - Undefined behavior
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);
printf("%d\n", *ptr);  // Use-after-free!
```

```rust
// Rust - Won't compile
let ptr = Box::new(42);
drop(ptr);            // Explicitly free
// println!("{}", ptr);  // ERROR: use of moved value
```

### Rust vs C Comparison Table

| Bug Type | C | Rust |
|----------|---|------|
| Buffer overflow | Runtime crash/corruption | Compile error or safe panic |
| Use-after-free | Undefined behavior | Compile error |
| Double-free | Corruption | Compile error |
| Data race | Undefined behavior | Compile error |
| Null pointer | Segfault | No null (Option<T> instead) |
| Memory leak | Possible | Prevented by Drop trait |

**Exam Question:** "What makes Rust safe that C is not?"

**Answer:** "Ownership system, borrow checker, compile-time enforcement"

---

## 13.6 Password Memory Safety

### Why Clearing Passwords Matters

**Exam Question (2022 Q5):** "Why should passwords be cleared from memory?"

**Model Answer:**
"Passwords in memory can be extracted through: (1) core dumps from crashes; (2) swap files written to disk; (3) memory debugging tools; (4) hibernation files; (5) cold boot attacks reading RAM; (6) vulnerabilities like Heartbleed reading process memory. Passwords should be cleared immediately after use with explicit zeroing that compilers can't optimize away (use `explicit_bzero()` or `memset_s()`). Regular `memset()` may be removed by compiler optimization as 'dead store'. In C, mark password buffers as `volatile` to prevent optimization. Minimize password lifetime in memory."

### Example 13: WRONG Password Handling

```c
// BAD - Multiple problems
void login(char *username, char *password) {
    char saved_password[100];
    load_password(username, saved_password);
    
    if (strcmp(password, saved_password) == 0) {
        printf("Login successful\n");
    }
    
    // password and saved_password still in memory!
    // Could be dumped if program crashes
    // Could be swapped to disk
}
```

### Example 14: CORRECT Password Handling

```c
#include <string.h>

void login(char *username, char *password) {
    volatile char saved_password[100];
    load_password(username, (char*)saved_password);
    
    int match = strcmp(password, (char*)saved_password);
    
    // Clear immediately after use
    explicit_bzero((char*)saved_password, sizeof(saved_password));
    
    if (match == 0) {
        printf("Login successful\n");
    }
}

// In main, also clear input password
void main() {
    volatile char password[100];
    get_password((char*)password);
    
    login(username, (char*)password);
    
    // Clear immediately
    explicit_bzero((char*)password, sizeof(password));
}
```

**Key points:**
- `volatile` prevents compiler optimization
- `explicit_bzero()` guaranteed not to be optimized away
- Clear ASAP after use
- Clear in all code paths (including errors)

---

## 13.7 Running Servers as Root (Critical Security)

### Why NEVER Run as Root

**Exam Question (2022 Q2):** "Why should you never run services as root?"

**Model Answer:**
"Running services as root violates the principle of least privilege. If the service has any vulnerability (buffer overflow, command injection, etc.), the attacker gains root access, allowing: complete system compromise, reading all files including `/etc/shadow`, installing rootkits, creating backdoor users, disabling logging, and pivoting to other systems. A web server only needs to read web files and bind to port 80/443 (which can be granted via capabilities without full root). If compromised as non-root user, damage is limited to that user's permissions. Use dedicated service accounts (e.g., `www-data`, `nobody`) with minimal permissions. Drop privileges after binding low ports."

### Example 15: Privilege Dropping

```c
#include <unistd.h>
#include <sys/types.h>

void start_server() {
    // Start as root to bind port 80
    bind_socket(80);
    
    // Immediately drop privileges
    if (setgid(33) != 0) {  // www-data group
        perror("setgid");
        exit(1);
    }
    
    if (setuid(33) != 0) {  // www-data user
        perror("setuid");
        exit(1);
    }
    
    // Now running as www-data
    // Even if exploited, attacker doesn't have root
    handle_requests();
}
```

---

## 13.8 Attack Payload Matching (ALWAYS ON EXAM)

### Recognizing Payloads

**Exam Pattern:** "Match attack to payload" or "What attack does this payload represent?"

| Payload | Attack Type |
|---------|-------------|
| `' OR 1=1 --` | SQL Injection (authentication bypass) |
| `' OR sleep(10); --` | Time-based SQL Injection |
| `'; DROP TABLE users; --` | SQL Injection (destructive) |
| `" OR "1"="1` | SQL Injection (double quotes) |
| `' UNION SELECT password FROM users--` | SQL Union-based injection |
| `admin' --` | SQL comment injection |
| `"; id #` | Command Injection (Unix) |
| `\| id` | Command Injection (pipe) |
| `&& whoami` | Command Injection (AND) |
| \`id\` | Command Injection (backticks) |
| `$(whoami)` | Command Injection (subshell) |
| `; sleep 10` | Blind Command Injection |
| `{{ 2+2 }}` | SSTI (Server-Side Template Injection) |
| `{{ 7*7 }}` | SSTI detection |
| `{{config}}` | SSTI (info disclosure) |
| `{%raw%}{{2+2}}{%endraw%}` | SSTI bypass attempt |
| `<script>alert(1)</script>` | XSS (Cross-Site Scripting) |
| `"><script>alert(1)</script>` | XSS (breaking out of attribute) |
| `<img src=x onerror=alert(1)>` | XSS (event handler) |
| `javascript:alert(1)` | XSS (URL scheme) |
| `http://127.0.0.1:8080` | SSRF (Server-Side Request Forgery) |
| `http://0.0.0.0:8081` | SSRF (accessing local services) |
| `http://169.254.169.254/latest/meta-data/` | SSRF (AWS metadata) |
| `http://localhost/admin` | SSRF (bypassing firewall) |
| `../../../etc/passwd` | Path Traversal |
| `....//....//etc/passwd` | Path Traversal (bypass filter) |
| `..%2F..%2F..%2Fetc%2Fpasswd` | Path Traversal (URL encoded) |
| `%p %p %p` | Format String vulnerability |
| `%x %x %x` | Format String (leak addresses) |
| `%s%s%s%s` | Format String (crash) |
| `%n` | Format String (write) |

### Example 16: Exam-Style Matching Question

**Question:** "Match each payload to its attack type:"

```
A. ' OR 1=1 --
B. {{ 7*7 }}
C. ; whoami
D. <script>alert(document.cookie)</script>
E. http://169.254.169.254

1. SSRF
2. XSS
3. SQL Injection
4. Command Injection
5. SSTI
```

**Answer:** A-3, B-5, C-4, D-2, E-1

---

## 13.9 Protection Mechanism Summary Table

**Exam will ask:** "What does X protection do?" or "How to bypass X?"

| Protection | What It Does | Bypass Method |
|------------|--------------|---------------|
| **Stack Canary** | Random value before return address, checked before return | Leak canary via format string, overwrite non-sequentially |
| **NX/DEP** | Marks stack/heap non-executable | ROP chains, ret2libc (reuse existing code) |
| **ASLR** | Randomizes memory addresses | Leak addresses via info disclosure, brute force on 32-bit |
| **PIE** | Randomizes executable base address | Leak code pointer, partial overwrite |
| **RELRO** | Makes GOT read-only | Can't overwrite GOT entries |
| **Shadow Stack** | Hardware-protected copy of return addresses | Nearly impossible to bypass, defeats ROP |
| **FORTIFY_SOURCE** | Adds bounds checking to string functions | Can't bypass if properly implemented |
| **Stack Clash Protection** | Guards against stack/heap collision | Targets very specific attack |

---

## 13.10 Common Exam Code Patterns

### Pattern 1: "What does this print?"

```assembly
section .data
    msg db "A"
    
section .text
global _start
_start:
    mov byte [msg], 0x42    ; 0x42 = 'B' in ASCII
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, 1
    syscall
    
    mov rax, 60
    mov rdi, 0
    syscall
```

**Answer:** "B"

### Pattern 2: "What is the exit code?"

```assembly
mov rax, 10
mov rbx, 3
sub rax, rbx        ; RAX = 7
mov rdi, rax
mov rax, 60
syscall
```

**Answer:** 7

### Pattern 3: "Is this vulnerable?"

```c
void process(char *input) {
    char buffer[100];
    strcpy(buffer, input);  // ← YES, vulnerable
}
```

**Answer:** Yes, strcpy has no bounds checking

### Pattern 4: "What sanitizer detects this?"

```c
int main() {
    int x = INT_MAX;
    x = x + 1;  // Integer overflow
    return 0;
}
```

**Answer:** UBSan (UndefinedBehaviorSanitizer)

### Pattern 5: "What attack is this?"

```python
url = request.args['url']
response = requests.get(url)  # No validation!
```

**Answer:** SSRF (Server-Side Request Forgery)

---

## 🎯 Exam Tips - Critical Knowledge

### MUST MEMORIZE

**Dangerous Functions:**
- gets(), strcpy(), strcat(), sprintf(), scanf("%s"), memcpy()

**Calling Convention (x86-64):**
- Arguments: RDI, RSI, RDX, RCX, R8, R9
- Return: RAX
- Syscall number: RAX

**Common Syscalls:**
- write: 1
- exit: 60
- execve: 59

**Memory Regions:**
- Stack: local vars, return addresses (grows DOWN)
- Heap: malloc() (grows UP)
- Text: code and string literals
- Data: initialized globals
- BSS: uninitialized globals

**Protections:**
- Canary: random value before return address
- NX: non-executable stack
- ASLR: randomized addresses
- PIE: randomized executable base

**Rust Safety:**
- Ownership: one owner per value
- Borrowing: multiple readers OR one writer
- Prevents: use-after-free, double-free, data races

**Security Principles:**
- Never run as root
- Clear passwords from memory (volatile, explicit_bzero)
- Least privilege
- Input validation (whitelist > blacklist)

---

## 📝 Quick Reference - Exam Patterns

**"What does this assembly do?"**
→ Track register values, identify syscall, find output/exit code

**"Which function is vulnerable?"**
→ gets(), strcpy(), scanf("%s") = vulnerable

**"What attack is this payload?"**
→ Match to table in section 13.8

**"Why is Rust safe?"**
→ Ownership, borrow checker, compile-time checks

**"Why not run as root?"**
→ Principle of least privilege, full compromise if exploited

**"What does [protection] do?"**
→ Refer to table in section 13.9

**"What sanitizer finds [bug]?"**
→ Integer overflow: UBSan
→ Buffer overflow: ASan
→ Uninitialized read: MSan
→ Data race: TSan

---

[← Previous: Create Your Own Vulnerabilities](./12-create-own-vulns.md) | [Back to Main →](../EXAM-PREP-README.md)
