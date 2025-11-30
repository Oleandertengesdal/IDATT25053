# 5. Buffer Overflow & Binary Exploitation - Complete Guide

## Overview
**EXTREMELY COMMON ON EXAM** - especially 2022 Q1 on ROP chains. You must understand stack layout and protection mechanisms.

---

## 5.1 Stack Memory Layout

### Stack Structure (x86-64)
```
High Memory
│
├─── Command line arguments
├─── Environment variables
├─── ...
├─── Stack Frame for main()
│    ├─── Return address
│    ├─── Saved base pointer (RBP)
│    ├─── Local variables
│    └─── Function arguments (if any)
│
├─── Stack Frame for called function
│    ├─── Return address      ← Overflow target!
│    ├─── Saved RBP
│    ├─── Local buffer        ← Overflow source
│    └─── ...
│
└─── Stack grows downward →
Low Memory
```

### Example 1: Simple Stack Layout

**Code:**
```c
void vulnerable(char *input) {
    char buffer[64];        // 64 bytes
    strcpy(buffer, input);  // No bounds check!
}

int main() {
    vulnerable(user_input);
    return 0;
}
```

**Stack when inside vulnerable():**
```
Address     | Content
------------|---------------------------
0x7fff0088  | Return address to main()  ← Overflow overwrites this!
0x7fff0080  | Saved RBP
0x7fff0040  | buffer[0..63]             ← Start writing here
0x7fff0000  | (lower stack)
```

---

## 5.2 Classic Buffer Overflow

### Attack Mechanism

**Question (2023 Q4 style):** "What can an attacker overwrite in a stack buffer overflow?"

**Answer:**
```
In order from buffer toward higher addresses, attacker can overwrite:

1. Local Variables (same stack frame):
   - Other buffers in the function
   - Function pointers
   - Flags/counters that control program logic

2. Saved Base Pointer (RBP):
   - Points to previous stack frame
   - Usually not directly exploitable
   - But needed for correct stack unwinding

3. Return Address:
   - Most critical target
   - Controls where execution continues after function returns
   - Attacker redirects to shellcode or ROP gadgets

4. Function Arguments (caller's frame):
   - Can modify parameters of calling function
   - Affects behavior after return

5. Stack Canary (if present):
   - Random value placed before return address
   - Checked before return
   - Overflow detected if canary modified
```

### Example 2: Exploitation Steps

**Vulnerable Program:**
```c
#include <string.h>
#include <stdio.h>

void secret() {
    printf("You found the secret!\n");
}

void vuln(char *input) {
    char buffer[32];
    strcpy(buffer, input);  // Overflow here
}

int main(int argc, char **argv) {
    vuln(argv[1]);
    return 0;
}
```

**Exploitation:**
```bash
# Find addresses
$ objdump -d vulnerable | grep secret
080484a0 <secret>:
  ...

# Find buffer offset to return address
$ gdb vulnerable
(gdb) info frame
# Buffer at offset 0, return address at offset 36 (32 bytes + 4 for saved RBP)

# Craft exploit
python3 -c "print('A'*36 + '\xa0\x84\x04\x08')" | ./vulnerable

Explanation:
'A' * 36          - Fill buffer + saved RBP
'\xa0\x84\x04\x08' - Overwrite return address with address of secret()
                     (little-endian format)

Result: Function returns to secret() instead of main()
```

---

## 5.3 Protection Mechanisms

### Stack Canary

**How it Works:**
```c
void function() {
    long canary = __stack_chk_guard;  // Random value
    char buffer[64];
    
    // ... function code ...
    
    if (canary != __stack_chk_guard)
        __stack_chk_fail();  // Abort!
    return;
}
```

**Stack Layout with Canary:**
```
0x7fff0088  | Return address
0x7fff0084  | Stack canary       ← Random value, checked before return
0x7fff0080  | Saved RBP
0x7fff0040  | buffer[64]
```

**Exam Question:** "How does a stack canary work?"

**Answer:**
"A stack canary is a random value placed on the stack between local buffers and the return address. Before the function returns, the canary value is checked against the original. If they differ, the buffer was overflowed and execution is terminated. Canaries prevent simple buffer overflows from reaching the return address. However, they can be bypassed if an attacker can read the canary value (via format string bug) or overwrite memory non-sequentially (via arbitrary write). Canaries add minimal performance overhead and are enabled by default with -fstack-protector."

**Bypassing Canary:**
```
Method 1: Information Leak
1. Use format string vulnerability to read canary from stack
2. Include correct canary in overflow payload
3. Canary check passes, overflow succeeds

Method 2: Partial Overwrite
1. Overwrite only parts of return address (not touching canary)
2. Works if target address differs in few bytes only

Method 3: Brute Force (32-bit)
1. Try all possible canary values
2. Feasible if program restarts with same canary
3. 2^32 attempts (hours to days)
```

### NX (No Execute) / DEP

**Exam Question:** "What is NX and how does it prevent exploits?"

**Answer:**
"NX (No Execute) or DEP (Data Execution Prevention) marks stack and heap memory as non-executable. This prevents traditional shellcode injection attacks where attackers place executable code in a buffer and jump to it. Modern CPUs enforce NX at the hardware level (NX bit on AMD, XD bit on Intel). When enabled, attempting to execute code from data regions causes a segmentation fault. Attackers bypass NX using return-oriented programming (ROP) or return-to-libc, which chains existing executable code rather than injecting new code. NX has negligible performance impact and is enabled by default on modern systems."

**Impact:**
```
Without NX:
1. Inject shellcode: buffer = "\x31\xc0\x50\x68..." (machine code)
2. Overflow return address to point to buffer
3. Execute shellcode directly

With NX:
1. Inject shellcode: buffer = "\x31\xc0\x50\x68..."
2. Overflow return address to buffer
3. CPU raises exception: "Attempted to execute non-executable memory"
4. Program crashes

Bypass: Use ROP (see section 5.4)
```

### ASLR (Address Space Layout Randomization)

**Exam Question:** "Explain ASLR and its limitations."

**Answer:**
"ASLR randomizes the base addresses of stack, heap, libraries, and executable sections at program startup. This makes hardcoded addresses in exploits unreliable, as target addresses differ on each run. ASLR significantly raises the exploitation difficulty, forcing attackers to find information leaks to discover current addresses. However, ASLR has limitations: on 32-bit systems, only 16 bits of entropy are practical, making brute force feasible; ASLR doesn't randomize the executable itself by default (need PIE); and pointer leaks completely defeat ASLR. Strong ASLR requires 64-bit systems with PIE enabled."

**Randomization Example:**
```
Without ASLR (addresses same every run):
$ ./program
Stack: 0xbffff000
Libc:  0xb7e00000

$ ./program
Stack: 0xbffff000  ← Same!
Libc:  0xb7e00000  ← Same!

With ASLR:
$ ./program
Stack: 0x7ffde000
Libc:  0x7f3e1000

$ ./program  
Stack: 0x7ffc8000  ← Different!
Libc:  0x7f221000  ← Different!
```

**Defeating ASLR:**
```
Method 1: Information Leak
1. Find vulnerability that leaks pointer (format string, buffer over-read)
2. Calculate base address from leaked address
3. Compute target addresses relative to base
4. Use correct addresses in exploit

Method 2: Brute Force (32-bit only)
1. Try many random addresses
2. Feasible with only 2^16 entropy
3. If program respawns, keep trying

Method 3: Partial Overwrite
1. Randomization only affects higher bytes
2. Overwrite only lower bytes
3. Partial addresses still useful in some cases
```

### PIE (Position Independent Executable)

**What it is:**
"Extends ASLR to the main executable code, not just libraries and stack."

**Without PIE:**
```
$ readelf -h program | grep Type
Type: EXEC (Executable file)

Main executable always loads at: 0x400000
Code addresses hardcoded and predictable
```

**With PIE:**
```
$ readelf -h program | grep Type
Type: DYN (Shared object file)

Main executable loads at: random address
All code addresses must be calculated at runtime
```

### Shadow Stack (Intel CET)

**Exam Question:** "What is a shadow stack and how does it prevent ROP?"

**Answer:**
"A shadow stack is a hardware-protected secondary stack that stores only return addresses, maintained in parallel with the regular stack. Introduced in Intel CET (Control-flow Enforcement Technology), it works by: (1) On function call, hardware writes return address to both regular stack and shadow stack; (2) On function return, hardware compares return addresses from both stacks; (3) If they don't match, processor raises an exception. This defeats ROP attacks because attackers can overwrite the regular stack but cannot access the shadow stack. Shadow stacks are stored in special memory protected by CPU, making them nearly impossible to bypass."

**How it blocks ROP:**
```
Regular Stack (attacker controls):
[buffer overflow]
[gadget1 address]
[gadget2 address]
[gadget3 address]

Shadow Stack (hardware protected):
[real return address]

When ret executes:
- Regular stack says: jump to gadget1
- Shadow stack says: jump to legitimate return
- MISMATCH → CPU exception → ROP blocked
```

---

## 5.4 ROP (Return-Oriented Programming)

### Concept

**Exam Question (2022 Q1 style):** "What is a ROP chain and how does it bypass NX?"

**Answer:**
"ROP (Return-Oriented Programming) bypasses NX by chaining together existing executable code fragments called 'gadgets'. Each gadget is a short instruction sequence ending in 'ret'. By carefully placing gadget addresses on the stack, an attacker controls program flow without injecting new code. When a function returns, it 'executes' the first gadget, which then 'returns' to the next gadget, creating a chain. ROP is Turing-complete, meaning arbitrary computations are possible. It defeats NX because all executed code was already present in executable memory. Modern mitigations include Control Flow Integrity (CFI) and shadow stacks."

### Gadgets

**Definition:** Small instruction sequences ending in `ret`

**Example Gadgets:**
```assembly
Gadget 1: pop rdi ; ret
   Address: 0x400686
   Effect: Loads value from stack into RDI register

Gadget 2: pop rsi ; ret
   Address: 0x400688
   Effect: Loads value from stack into RSI register

Gadget 3: mov rax, 0x3b ; ret
   Address: 0x40070a
   Effect: Sets RAX to 59 (sys_execve number)

Gadget 4: syscall ; ret
   Address: 0x400742
   Effect: Makes system call with current registers
```

### Example 3: Building a ROP Chain

**Goal:** Call `execve("/bin/sh", NULL, NULL)`

**Syscall requirements:**
```
RAX = 59 (sys_execve number)
RDI = pointer to "/bin/sh"
RSI = NULL
RDX = NULL
```

**ROP Chain Construction:**
```
Stack setup:
0x7fff00a0  | 0x400686     ← pop rdi ; ret
0x7fff00a8  | 0x601050     ← address of "/bin/sh" string
0x7fff00b0  | 0x400688     ← pop rsi ; ret
0x7fff00b8  | 0x0          ← NULL
0x7fff00c0  | 0x40068a     ← pop rdx ; ret
0x7fff00c8  | 0x0          ← NULL
0x7fff00d0  | 0x40070a     ← mov rax, 0x3b ; ret
0x7fff00d8  | 0x400742     ← syscall

Execution flow:
1. Return to 0x400686 (pop rdi ; ret)
   - Pops 0x601050 into RDI
   - Returns to next address (0x400688)

2. Execute 0x400688 (pop rsi ; ret)
   - Pops 0x0 into RSI
   - Returns to 0x40068a

3. Execute 0x40068a (pop rdx ; ret)
   - Pops 0x0 into RDX
   - Returns to 0x40070a

4. Execute 0x40070a (mov rax, 0x3b ; ret)
   - Sets RAX = 59
   - Returns to 0x400742

5. Execute 0x400742 (syscall)
   - Calls execve("/bin/sh", NULL, NULL)
   - Spawns shell!
```

### Finding Gadgets

**Tools:**
```bash
# ROPgadget
$ ROPgadget --binary program
Gadgets information
============================================================
0x0000000000400686 : pop rdi ; ret
0x0000000000400688 : pop rsi ; pop r15 ; ret
0x000000000040070a : mov rax, 0x3b ; ret
...

# ropper
$ ropper --file program --search "pop rdi"
0x00000000004005a3: pop rdi; ret;
```

---

## 🎯 Exam Tips for Buffer Overflow

### Must Know

1. **Stack Layout**
   - Draw it on exam
   - Show what overflows what

2. **Protection Mechanisms**
   - Know how each works
   - How to bypass each

3. **ROP Basics**
   - What are gadgets
   - How chain executes
   - Why it bypasses NX

### Common Questions

**"What can be overwritten?"**
```
In order:
1. Other local variables
2. Saved RBP
3. Return address (most critical)
4. Arguments to calling function
```

**"How do protections work together?"**
```
Defense in Depth:
- Stack Canary: Detect overflow before return
- NX: Prevent shellcode execution
- ASLR: Randomize addresses
- PIE: Randomize code addresses

All must be bypassed for successful exploit
```

---

## 📝 Quick Reference

```
STACK LAYOUT:
[High Memory]
  Return Address  ← Control flow target
  Saved RBP      ← Frame pointer
  Local Buffer   ← Overflow source
[Low Memory]

PROTECTIONS:
Canary: Random value checked before return
NX: Mark stack/heap non-executable  
ASLR: Randomize memory layout
PIE: Randomize executable code

ROP:
Gadget: short code + ret
Chain: sequence of gadget addresses on stack
Bypasses: NX (uses existing code)
Defeated by: CFI, shadow stacks

GDB COMMANDS:
info frame          - Show stack frame
x/20x $rsp          - Examine stack
pattern create 100  - Generate unique pattern
pattern offset 0x41 - Find offset to EIP
```

---

[← Previous: Symmetric & AES](./04-symmetric-aes.md) | [Next: Web Vulnerabilities →](./06-web-vulnerabilities.md)
