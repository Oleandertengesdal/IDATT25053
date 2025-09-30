# Reverse Engineering Cheatsheet

Quick reference for reverse engineering tools, techniques, and methodologies.

## 📚 Table of Contents

- [Reverse Engineering Basics](#reverse-engineering-basics)
- [Static Analysis Tools](#static-analysis-tools)
- [Dynamic Analysis Tools](#dynamic-analysis-tools)
- [Disassembly & Decompilation](#disassembly--decompilation)
- [Common Patterns](#common-patterns)
- [Anti-Debugging Techniques](#anti-debugging-techniques)
- [Resources](#resources)

## 🔍 Reverse Engineering Basics

### Information Gathering

```bash
# File type
file binary

# Strings in binary
strings binary
strings -e l binary  # Little-endian 16-bit (Unicode)

# Library dependencies
ldd binary

# Symbol table
nm binary
objdump -T binary

# Headers
readelf -h binary
readelf -S binary  # Section headers
readelf -l binary  # Program headers

# Checksec protections
checksec binary
```

## 🛠️ Static Analysis Tools

### Ghidra

**Installation:**
```bash
# Download from https://ghidra-sre.org/
unzip ghidra_*.zip
cd ghidra_*/
./ghidraRun
```

**Workflow:**
1. Create new project
2. Import binary (File → Import File)
3. Analyze (Yes to all default analyzers)
4. Navigate to functions (Symbol Tree → Functions)
5. Double-click main or entry point

**Keyboard Shortcuts:**
- `G` - Go to address
- `L` - Rename variable/function
- `T` - Retype variable
- `;` - Add comment
- `Ctrl+Shift+E` - Edit function signature
- `D` - Disassemble
- `F` - Create function

**Scripting (Python):**
```python
# Ghidra Python script example
from ghidra.program.model.symbol import SourceType

# Get current program
program = getCurrentProgram()

# List all functions
fm = program.getFunctionManager()
for func in fm.getFunctions(True):
    print(f"{func.getName()} at {func.getEntryPoint()}")

# Rename function
func = getFunctionAt(toAddr(0x401000))
func.setName("custom_name", SourceType.USER_DEFINED)
```

### IDA Pro / IDA Free

**Keyboard Shortcuts:**
- `G` - Jump to address
- `N` - Rename
- `Y` - Change type
- `;` - Add comment
- `/` - Add repeatable comment
- `X` - Cross-references to
- `Ctrl+X` - Cross-references from
- `Space` - Toggle graph/text view
- `Esc` - Go back

**IDAPython:**
```python
# Get function at address
func = idaapi.get_func(0x401000)

# Get function name
func_name = idc.get_func_name(0x401000)

# Rename
idc.set_name(0x401000, "new_name")

# Get string at address
string = idc.get_strlit_contents(0x402000)
```

### Radare2

**Basic Commands:**
```bash
# Open binary
r2 binary

# Analyze all
[0x00000000]> aaa

# List functions
[0x00000000]> afl

# Disassemble function
[0x00000000]> pdf @ main

# Seek to address
[0x00000000]> s 0x401000

# Print hex
[0x00401000]> px 64

# Print strings
[0x00000000]> iz

# Visual mode
[0x00000000]> VV

# Graph mode
[0x00000000]> VV

# Debug mode
r2 -d binary
```

**Radare2 Commands Reference:**
```
a     - Analysis
aa    - Analyze all
afl   - List functions
pdf   - Print disassembly of function
s     - Seek
px    - Print hexadecimal
iz    - List strings in data sections
V     - Visual mode
VV    - Visual graph mode
?     - Help
```

### Binary Ninja

**Features:**
- Clean decompiler (HLIL)
- Medium-Level IL (MLIL)
- Low-Level IL (LLIL)
- Python API

**Python API:**
```python
import binaryninja as bn

# Open binary
bv = bn.open_view('/path/to/binary')

# Get functions
for func in bv.functions:
    print(f"{func.name} at {hex(func.start)}")

# Get decompiled code
for func in bv.functions:
    if func.name == 'main':
        print(func.hlil)
```

## 🔬 Dynamic Analysis Tools

### GDB with GEF/pwndbg

**Installation:**
```bash
# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# PEDA
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

**Essential GDB Commands:**
```bash
# Breakpoints
break main
break *0x401234
break function_name

# Running
run
run arg1 arg2
run < input.txt

# Stepping
step (s)         # Step into
next (n)         # Step over
stepi (si)       # Step instruction
nexti (ni)       # Next instruction
continue (c)     # Continue
finish           # Run until return

# Examining
info registers
info functions
info breakpoints
x/20x $rsp       # Examine 20 hex values at RSP
x/s 0x402000     # Examine string
x/i $rip         # Examine instruction
disassemble main

# Watching
watch variable
watch *0x601234

# Stack trace
backtrace (bt)
frame 0
```

**GEF Specific:**
```bash
vmmap                    # Memory mappings
checksec                 # Security features
pattern create 200       # Create cyclic pattern
pattern search $rsp      # Find pattern offset
heap chunks              # Show heap chunks
elf-info                 # ELF information
search-pattern "/bin/sh" # Search memory
xinfo 0x401000          # Detailed info about address
```

### ltrace / strace

```bash
# Trace library calls
ltrace ./binary

# Trace system calls
strace ./binary

# Filter specific calls
ltrace -e malloc+free ./binary
strace -e open,read,write ./binary

# Follow forks
strace -f ./binary

# Output to file
ltrace -o trace.log ./binary
```

### Frida

**Installation:**
```bash
pip install frida-tools
```

**Basic Usage:**
```javascript
// Attach to process
frida -p <pid> -l script.js

// Spawn and instrument
frida -f ./binary -l script.js
```

**Frida Script Example:**
```javascript
// Hook function
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        console.log("strcmp called");
        console.log("arg1: " + Memory.readUtf8String(args[0]));
        console.log("arg2: " + Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("Return value: " + retval);
        // Modify return value
        retval.replace(0);
    }
});

// Read memory
var addr = ptr("0x401000");
console.log(hexdump(addr, { length: 64 }));

// Write memory
Memory.writeUtf8String(addr, "newstring");
```

## 📖 Disassembly & Decompilation

### x86-64 Assembly Basics

**Registers:**
```
64-bit: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15
32-bit: EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, R8D-R15D
16-bit: AX, BX, CX, DX, SI, DI, BP, SP, R8W-R15W
8-bit:  AL, BL, CL, DL, SIL, DIL, BPL, SPL, R8B-R15B
```

**Common Instructions:**
```assembly
; Data movement
mov rax, rbx      ; rax = rbx
lea rax, [rbx+8]  ; rax = address of rbx+8
push rax          ; Push rax onto stack
pop rbx           ; Pop stack into rbx

; Arithmetic
add rax, rbx      ; rax += rbx
sub rax, rbx      ; rax -= rbx
imul rax, rbx     ; rax *= rbx (signed)
xor rax, rax      ; rax = 0 (common idiom)

; Comparison & jumps
cmp rax, rbx      ; Compare (subtract without storing)
test rax, rax     ; AND without storing (check if zero)
je target         ; Jump if equal
jne target        ; Jump if not equal
jg target         ; Jump if greater
jl target         ; Jump if less

; Function calls
call function     ; Call function
ret               ; Return from function
```

**Calling Conventions (System V x86-64):**
```
Arguments (in order):
1. RDI
2. RSI
3. RDX
4. RCX
5. R8
6. R9
7+ Stack (right to left)

Return value: RAX
Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
Callee-saved: RBX, RBP, R12-R15
```

### Recognizing Common Patterns

**if-else Statement:**
```assembly
; if (a < b)
cmp eax, ebx
jge else_label
  ; then block
  mov ecx, 1
  jmp end_if
else_label:
  ; else block
  mov ecx, 0
end_if:
```

**while Loop:**
```assembly
loop_start:
  cmp eax, 10
  jge loop_end
  ; loop body
  add eax, 1
  jmp loop_start
loop_end:
```

**for Loop:**
```assembly
; for (i = 0; i < 10; i++)
  xor eax, eax       ; i = 0
loop_start:
  cmp eax, 10
  jge loop_end
  ; loop body
  add eax, 1         ; i++
  jmp loop_start
loop_end:
```

**Function Prologue:**
```assembly
push rbp
mov rbp, rsp
sub rsp, 0x20      ; Allocate local variables
```

**Function Epilogue:**
```assembly
mov rsp, rbp
pop rbp
ret
```

**Switch Statement (Jump Table):**
```assembly
cmp eax, 5
ja default_case
lea rdx, [jump_table]
mov rax, [rdx + rax*8]
jmp rax

jump_table:
  dq case_0
  dq case_1
  dq case_2
  ...
```

## 🛡️ Anti-Debugging Techniques

### Common Anti-Debug Tricks

**1. IsDebuggerPresent:**
```c
if (IsDebuggerPresent()) {
    exit(1);
}
```

**Bypass:**
```bash
# Patch in Ghidra/IDA/x64dbg
# Change jne to jmp or nop the check
```

**2. PTrace Anti-Debug (Linux):**
```c
if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
    printf("Debugger detected!\n");
    exit(1);
}
```

**Bypass:**
```bash
# LD_PRELOAD a library that overrides ptrace
gcc -shared -fPIC -o ptrace_bypass.so ptrace_bypass.c
LD_PRELOAD=./ptrace_bypass.so ./binary
```

**3. Timing Checks:**
```c
time_t start = time(NULL);
// Some code
if (time(NULL) - start > 1) {
    // Debugger detected (too slow)
}
```

**Bypass:**
```
# Patch timing comparison
# Or use hardware breakpoints (faster)
```

**4. Checking /proc/self/status:**
```c
FILE *fp = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        if (atoi(line + 11) != 0) {
            // Debugger detected
        }
    }
}
```

### Defeating Anti-Debug

```bash
# Use Frida to hook anti-debug functions
frida -f ./binary -l hook_antidebug.js

# Patch binary to remove checks
# Use debugger that's harder to detect
# Emulate the binary (QEMU, Unicorn)
```

## 🎓 Reverse Engineering Workflow

1. **Reconnaissance**
   ```bash
   file binary
   strings binary | less
   checksec binary
   ```

2. **Static Analysis**
   ```bash
   # Quick look
   objdump -d binary | less
   
   # Deep analysis
   ghidra binary
   ```

3. **Dynamic Analysis**
   ```bash
   ltrace ./binary
   strace ./binary
   gdb ./binary
   ```

4. **Understanding Algorithm**
   - Identify main function
   - Trace execution flow
   - Identify key functions
   - Reconstruct algorithm

5. **Documentation**
   - Comment functions
   - Name variables
   - Draw flowcharts
   - Write pseudocode

## 📝 Tips & Tricks

### Quick Win Techniques

**1. Check for Hardcoded Secrets:**
```bash
strings binary | grep -i password
strings binary | grep -i key
strings binary | grep -i secret
```

**2. Find Main Function:**
```bash
# Entry point calls __libc_start_main
# First argument to __libc_start_main is main()
```

**3. Identify Interesting Functions:**
```bash
# Look for:
- strcmp/strncmp (password checks)
- system/exec (command execution)
- fopen/fread (file operations)
- socket/connect (network operations)
```

**4. Patch Binary:**
```bash
# Using radare2
r2 -w binary
[0x00000000]> s 0x401234
[0x00401234]> wa nop
[0x00401234]> wa "mov eax, 1; ret"
```

**5. Extract Embedded Files:**
```bash
binwalk binary
binwalk -e binary  # Extract
foremost binary
```

### Common Decompiler Patterns

**Obfuscated String:**
```c
// Decompiled code
char buf[10] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0};
// Translates to: "Hello"
```

**XOR Encryption:**
```c
for (int i = 0; i < len; i++) {
    data[i] ^= 0x42;  // Simple XOR cipher
}
```

**Virtual Function Table:**
```c
// C++ object with vtable
struct Object {
    void (**vtable)(struct Object*);
    int data;
};
```

## 📚 Resources

### Books
- "Practical Reverse Engineering" by Bruce Dang
- "The IDA Pro Book" by Chris Eagle
- "Reversing: Secrets of Reverse Engineering" by Eldad Eilam

### Online Resources
- [Reverse Engineering for Beginners](https://beginners.re/)
- [Malware Unicorn Workshops](https://malwareunicorn.org/)
- [Nightmare (RE Course)](https://guyinatuxedo.github.io/)

### Practice Sites
- [Crackmes.one](https://crackmes.one/)
- [Reverse Engineering Challenges](https://challenges.re/)
- [RingZer0 Team](https://ringzer0ctf.com/)

---

**Remember**: Always ensure you have permission before reverse engineering software!
