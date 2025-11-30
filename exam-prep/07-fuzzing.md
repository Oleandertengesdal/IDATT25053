# 7. Fuzzing & Sanitizers - Complete Guide

## Overview
Appears every year. Know **undefined behavior**, what **sanitizers detect**, and how **fuzzers work**.

---

## 7.1 Fuzzing Basics

### Definition
**Fuzzing** is automated testing technique that feeds invalid, unexpected, or random data to a program to find bugs.

**Exam Question:** "What is fuzzing?"

**Answer:**
"Fuzzing is an automated software testing technique that provides invalid, unexpected, or random data as input to a program to discover bugs, crashes, and security vulnerabilities. A fuzzer generates test cases (often by mutating valid inputs), executes the target program with each test case, and monitors for crashes, hangs, or unexpected behavior. Modern fuzzers use coverage-guided techniques, generating inputs that explore new code paths to maximize bug discovery. Fuzzing is effective at finding memory corruption, assertion failures, and logic errors that are difficult to find through manual testing or code review."

### Types of Fuzzers

#### Mutation-based (Dumb Fuzzing)
```
Takes valid input and randomly mutates it:

Original: "GET / HTTP/1.1\r\n"
Mutated:  "GET / HTTP/1.999\r\n"
Mutated:  "GETAAAAA / HTTP/1.1\r\n"
Mutated:  "GET / HTTP/1.\x00\r\n"

Pros: No knowledge of format required
Cons: Inefficient, may not reach deep code paths
```

#### Generation-based (Smart Fuzzing)
```
Generates inputs from grammar/format specification:

Grammar: HTTP request = METHOD + " " + PATH + " HTTP/" + VERSION
Valid generated inputs:
- "POST /api HTTP/1.0"
- "DELETE /admin HTTP/2.0"
- "OPTIONS * HTTP/1.1"

Pros: Better coverage, respects structure
Cons: Requires format specification
```

#### Coverage-guided (Modern approach)
```
Uses code coverage feedback to guide input generation:

1. Run program with input A
2. Measure which code branches taken
3. If new branches found → save input A
4. Mutate saved inputs to find more branches
5. Repeat

Example: AFL (American Fuzzy Lop), libFuzzer

Pros: Efficient, finds deep bugs
Cons: Requires instrumentation
```

---

## 7.2 Code Coverage

### Types of Coverage

**Example 1: Understanding Coverage**
```c
int process(int x, int y) {
    if (x > 0) {          // Branch 1
        if (y > 0) {      // Branch 2
            return x + y; // Path A
        } else {
            return x - y; // Path B
        }
    } else {
        return 0;         // Path C
    }
}
```

**Coverage Metrics:**
```
Line Coverage:
- Measures which lines executed
- Test: process(1, 1) → covers lines in if(x>0) and if(y>0)
- 100% line coverage possible without testing all branches

Branch Coverage:
- Measures which branches (if/else) taken
- Need tests for: x>0&&y>0, x>0&&y<=0, x<=0
- Better than line coverage

Path Coverage:
- Measures which execution paths taken  
- Paths: A (x>0,y>0), B (x>0,y<=0), C (x<=0)
- Most thorough but exponentially complex

Edge Coverage:
- Measures transitions between basic blocks
- Used by AFL/libFuzzer
- Efficient middle ground
```

### Example 2: Coverage-Guided Fuzzing

```c
void parse_format(char *input) {
    if (input[0] == 'M') {          // Coverage: hit branch 1
        if (input[1] == 'A') {      // Coverage: hit branch 2
            if (input[2] == 'G') {  // Coverage: hit branch 3
                if (input[3] == 'I') {
                    if (input[4] == 'C') {
                        // Deep bug here!
                        char buf[4];
                        strcpy(buf, input + 5); // Overflow!
                    }
                }
            }
        }
    }
}
```

**Fuzzing progression:**
```
Input 1: "A" 
→ Branch 1 not taken → discard

Input 2: "M"
→ Branch 1 taken! → save to corpus

Input 3: "MA" (mutate saved input)
→ Branch 2 taken! → save

Input 4: "MAG"
→ Branch 3 taken! → save

Input 5: "MAGI"
Input 6: "MAGIC"
→ Crash! Found bug

Without coverage guidance: Would need ~256^5 = 1 trillion attempts
With coverage: Found in ~10 iterations
```

---

## 7.3 Undefined Behavior

### Common Types

**Exam Question (2023 Q8 style):** "What types of undefined behavior do sanitizers find?"

**Answer:**
```
Sanitizers detect various forms of undefined behavior:

1. Memory Errors:
   - Buffer overflows (read/write past bounds)
   - Use-after-free (accessing freed memory)
   - Double-free (freeing same memory twice)
   - Memory leaks (allocated but never freed)

2. Uninitialized Memory:
   - Reading variables before initialization
   - Using uninitialized values in conditionals

3. Integer Errors:
   - Signed integer overflow
   - Division by zero
   - Shift by too many bits

4. Pointer Errors:
   - Null pointer dereference
   - Invalid pointer arithmetic
   - Misaligned pointer access

5. Data Races:
   - Multiple threads accessing same memory without synchronization
   - Race conditions in concurrent code

These bugs often don't crash immediately but cause security
vulnerabilities, incorrect behavior, or crashes in production.
```

### Example 3: Buffer Overflow
```c
// Undefined behavior: buffer overflow
char buffer[10];
strcpy(buffer, "This is too long!");  // Writes past buffer[9]

// What happens:
// - Overwrites adjacent memory
// - May corrupt other variables
- May overwrite return address
// - Behavior is UNDEFINED (anything can happen)

ASan output:
==12345==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 18 at 0x7fff1234 thread T0
```

### Example 4: Use-After-Free
```c
// Undefined behavior: use-after-free
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);
printf("%d\n", *ptr);  // Reading freed memory!

// What happens:
// - Memory might be reallocated
// - Might contain different data
// - Might crash, might not
// - Security issue: attacker can control freed memory

ASan output:
==12345==ERROR: AddressSanitizer: heap-use-after-free
READ of size 4 at 0x602000000010 thread T0
```

### Example 5: Integer Overflow
```c
// Undefined behavior: signed integer overflow
int a = INT_MAX;  // 2147483647
int b = a + 1;    // Overflow! Undefined behavior

// Common result: wraps to INT_MIN (-2147483648)
// But compiler can assume this never happens!
// May optimize away overflow checks

UBSan output:
runtime error: signed integer overflow: 2147483647 + 1 
cannot be represented in type 'int'
```

### Example 6: Uninitialized Memory
```c
// Undefined behavior: uninitialized read
int x;              // Not initialized
if (x > 0) {        // Reading garbage!
    do_something();
}

// What happens:
// - x contains whatever was in memory
// - Behavior depends on previous stack contents
// - Non-deterministic bugs
// - Information leak (might contain sensitive data)

MSan output:
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
```

---

## 7.4 Sanitizers

### AddressSanitizer (ASan)

**What it detects:**
```
- Heap buffer overflow
- Stack buffer overflow
- Global buffer overflow
- Use-after-free
- Use-after-return
- Use-after-scope
- Double-free
- Memory leaks (with LeakSanitizer)
```

**How it works:**
```
1. Instruments memory operations at compile time
2. Adds "red zones" around allocations
3. Marks freed memory as poisoned
4. On each memory access, checks if address is poisoned
5. If poisoned → report error with stack trace

Performance: ~2x slowdown
Memory: ~3x usage
```

**Usage:**
```bash
# Compile with ASan
$ gcc -fsanitize=address -g program.c -o program

# Run
$ ./program
# If error: detailed report with stack traces
```

### UndefinedBehaviorSanitizer (UBSan)

**What it detects:**
```
- Signed integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointer
- Shift errors (shift by negative, shift by too much)
- Invalid bool/enum values
- Out-of-bounds array access
```

**Usage:**
```bash
$ gcc -fsanitize=undefined -g program.c -o program
```

### MemorySanitizer (MSan)

**What it detects:**
```
- Use of uninitialized memory
- Tracks initialization at bit level
```

**Usage:**
```bash
$ clang -fsanitize=memory -g program.c -o program
```

### ThreadSanitizer (TSan)

**What it detects:**
```
- Data races between threads
- Use of non-thread-safe APIs
```

**Usage:**
```bash
$ gcc -fsanitize=thread -g program.c -o program
```

---

## 7.5 Fuzzing in Practice

### Example 7: AFL Setup

**Target program (fuzz_target.c):**
```c
#include <stdio.h>
#include <string.h>

void process_input(char *data, size_t len) {
    if (len >= 4) {
        if (data[0] == 'F') {
            if (data[1] == 'U') {
                if (data[2] == 'Z') {
                    if (data[3] == 'Z') {
                        // Bug!
                        char buf[4];
                        strcpy(buf, data + 4); // Overflow
                    }
                }
            }
        }
    }
}

int main() {
    char buffer[1024];
    size_t len = fread(buffer, 1, sizeof(buffer), stdin);
    process_input(buffer, len);
    return 0;
}
```

**Fuzzing setup:**
```bash
# Compile with AFL instrumentation
$ afl-gcc -fsanitize=address fuzz_target.c -o fuzz_target

# Create input directory
$ mkdir inputs
$ echo "FUZZ" > inputs/seed.txt

# Run fuzzer
$ afl-fuzz -i inputs -o outputs ./fuzz_target

# AFL will:
# 1. Mutate "FUZZ" seed
# 2. Track coverage
# 3. Find crash when input = "FUZZ" + overflow data
```

### Example 8: LibFuzzer

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 4) {
        if (data[0] == 'F' &&
            data[1] == 'U' &&
            data[2] == 'Z' &&
            data[3] == 'Z') {
            // Bug!
            char buf[4];
            memcpy(buf, data + 4, size - 4); // Overflow!
        }
    }
    return 0;
}
```

**Compile and run:**
```bash
$ clang -fsanitize=fuzzer,address fuzz_target.c -o fuzzer
$ ./fuzzer

# LibFuzzer continuously generates inputs
# Crash found: artifact written to crash-...
```

---

## 7.6 Corpus and Seeds

**Corpus:** Collection of test inputs that provide good coverage

**Exam Question:** "What is a corpus in fuzzing?"

**Answer:**
"A corpus is the collection of inputs (test cases) maintained by a fuzzer that achieve unique code coverage. As the fuzzer explores the program, inputs that trigger new code paths are added to the corpus. These corpus inputs are then mutated to generate new test cases, creating a feedback loop. A good corpus provides diverse coverage with minimal redundant inputs. Fuzzers can start with a seed corpus of example valid inputs. Over time, the corpus grows to include edge cases and inputs that reach deep program states. Maintaining a high-quality corpus is essential for efficient fuzzing."

**Example workflow:**
```
Initial corpus: ["GET / HTTP/1.1", "POST /api HTTP/1.1"]
↓
Fuzzer mutates and finds new coverage
↓
Expanded corpus: [original + "GET /../ HTTP/1.1", "OPTIONS * HTTP/1.1", ...]
↓
Continue mutating expanded corpus
↓
Eventually finds crash with specific input
```

---

## 🎯 Exam Tips for Fuzzing

### Key Concepts

1. **What fuzzing does:** Automated testing with random/mutated inputs
2. **Types:** Mutation vs generation vs coverage-guided
3. **Coverage:** Line < branch < path, fuzzers use edge coverage
4. **Sanitizers:** Detect UB that doesn't always crash
5. **Corpus:** Saved inputs that find new coverage

### Common Questions

**"How does AFL work?"**
```
1. Instrument code to track edges
2. Mutate inputs from corpus
3. Execute program with mutated input
4. If new edge covered → add to corpus
5. Repeat millions of times
```

**"Why use sanitizers with fuzzing?"**
```
Many bugs don't crash immediately:
- Buffer overflow might overwrite unused memory
- Use-after-free might read valid data by chance
- Integer overflow might not affect program

Sanitizers detect these immediately:
- Faster bug discovery
- More detailed error reports
- Find bugs that would be missed
```

---

## 📝 Quick Reference

```
FUZZING:
- Mutation: Random changes to inputs
- Coverage-guided: Prioritize inputs finding new code paths
- Corpus: Collection of interesting inputs

UNDEFINED BEHAVIOR:
- Buffer overflow/underflow
- Use-after-free
- Double-free
- Uninitialized reads
- Integer overflow
- Null dereference

SANITIZERS:
ASan: Memory errors (overflow, UAF, double-free)
UBSan: Undefined behavior (overflow, div-by-zero)
MSan: Uninitialized memory
TSan: Data races

COMPILE FLAGS:
-fsanitize=address
-fsanitize=undefined
-fsanitize=memory
-fsanitize=thread
-fsanitize=fuzzer (libFuzzer)
```

---

[← Previous: Web Vulnerabilities](./06-web-vulnerabilities.md) | [Next: Pentest Methodology →](./08-pentest-methodology.md)
