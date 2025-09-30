# Sanitizers Cheatsheet

Quick reference for memory and security sanitizers: AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer.

## 📚 Table of Contents

- [Overview](#overview)
- [AddressSanitizer (ASan)](#addresssanitizer-asan)
- [MemorySanitizer (MSan)](#memorysanitizer-msan)
- [UndefinedBehaviorSanitizer (UBSan)](#undefinedbehaviorsanitizer-ubsan)
- [ThreadSanitizer (TSan)](#threadsanitizer-tsan)
- [LeakSanitizer (LSan)](#leaksanitizer-lsan)
- [Combining Sanitizers](#combining-sanitizers)
- [CI/CD Integration](#cicd-integration)

## 🔍 Overview

Sanitizers are runtime code instrumentation tools that detect bugs and undefined behavior in C/C++ programs.

| Sanitizer | Detects | Performance Overhead |
|-----------|---------|---------------------|
| **ASan** | Memory errors (overflow, UAF, etc.) | ~2x |
| **MSan** | Uninitialized memory reads | ~3x |
| **UBSan** | Undefined behavior | ~1.2x |
| **TSan** | Data races, deadlocks | ~5-15x |
| **LSan** | Memory leaks | Minimal |

## 🛡️ AddressSanitizer (ASan)

### What It Detects

- Heap buffer overflow/underflow
- Stack buffer overflow/underflow
- Global buffer overflow
- Use-after-free
- Use-after-return
- Use-after-scope
- Double-free
- Memory leaks (via LeakSanitizer)

### Compilation

```bash
# GCC/Clang
gcc -fsanitize=address -g -O1 program.c -o program
g++ -fsanitize=address -g -O1 program.cpp -o program

# With optimization (recommended)
clang -fsanitize=address -g -O1 program.c -o program

# Detect more issues
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 program.c -o program
```

### Running

```bash
# Basic run
./program

# With options
ASAN_OPTIONS=check_initialization_order=1:detect_stack_use_after_return=1 ./program

# Save report to file
ASAN_OPTIONS=log_path=asan.log ./program
```

### Common Issues Detected

**1. Heap Buffer Overflow:**
```c
int main() {
    int *array = malloc(100 * sizeof(int));
    array[100] = 0;  // Out of bounds!
    free(array);
    return 0;
}
```

**ASan Output:**
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 0x... in main program.c:3
```

**2. Use-After-Free:**
```c
int main() {
    int *ptr = malloc(sizeof(int));
    free(ptr);
    *ptr = 42;  // Use after free!
    return 0;
}
```

**3. Stack Buffer Overflow:**
```c
void vulnerable() {
    char buffer[10];
    strcpy(buffer, "This is too long!");  // Overflow!
}
```

### ASan Environment Variables

```bash
# Check initialization order
ASAN_OPTIONS=check_initialization_order=1

# Detect stack use-after-return
ASAN_OPTIONS=detect_stack_use_after_return=1

# Abort on first error
ASAN_OPTIONS=halt_on_error=1

# Disable leak detection
ASAN_OPTIONS=detect_leaks=0

# Custom log path
ASAN_OPTIONS=log_path=/tmp/asan.log

# Symbolize stack traces
ASAN_OPTIONS=symbolize=1

# Multiple options
ASAN_OPTIONS=check_initialization_order=1:detect_stack_use_after_return=1:halt_on_error=0
```

## 🧠 MemorySanitizer (MSan)

### What It Detects

- Reads of uninitialized memory
- Use of uninitialized values in control flow
- Passing uninitialized data to system calls

### Compilation

```bash
# Clang only (not available in GCC)
clang -fsanitize=memory -g -O1 program.c -o program

# With track-origins (more detailed reports)
clang -fsanitize=memory -fsanitize-memory-track-origins -g -O1 program.c -o program
```

### Example

```c
#include <stdio.h>

int main() {
    int x;
    printf("%d\n", x);  // Uninitialized read!
    return 0;
}
```

**MSan Output:**
```
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x... in main program.c:5
```

### MSan Environment Variables

```bash
# Exit on first error
MSAN_OPTIONS=halt_on_error=1

# Print statistics
MSAN_OPTIONS=print_stats=1

# Custom log path
MSAN_OPTIONS=log_path=/tmp/msan.log
```

## ⚠️ UndefinedBehaviorSanitizer (UBSan)

### What It Detects

- Integer overflow/underflow
- Division by zero
- Null pointer dereference
- Misaligned pointer access
- Invalid type casts
- Shift operations with invalid counts
- Out-of-bounds array access (with bounds checking)
- Unreachable code execution

### Compilation

```bash
# GCC/Clang
gcc -fsanitize=undefined -g program.c -o program

# Specific checks
gcc -fsanitize=signed-integer-overflow,null,bounds program.c -o program

# All checks except specific ones
gcc -fsanitize=undefined -fno-sanitize=alignment program.c -o program
```

### UBSan Checks

```bash
# Available checks:
-fsanitize=shift                  # Invalid shift operations
-fsanitize=integer-divide-by-zero # Division by zero
-fsanitize=null                   # Null pointer dereference
-fsanitize=signed-integer-overflow # Signed integer overflow
-fsanitize=bounds                 # Array bounds checking
-fsanitize=alignment              # Misaligned access
-fsanitize=object-size            # Object size violations
-fsanitize=vptr                   # Invalid virtual pointer
```

### Examples

**1. Integer Overflow:**
```c
#include <limits.h>

int main() {
    int x = INT_MAX;
    x = x + 1;  // Signed integer overflow!
    return 0;
}
```

**UBSan Output:**
```
program.c:5:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
```

**2. Division by Zero:**
```c
int main() {
    int x = 10;
    int y = 0;
    int z = x / y;  // Division by zero!
    return 0;
}
```

**3. Null Pointer Dereference:**
```c
int main() {
    int *ptr = NULL;
    *ptr = 42;  // Null dereference!
    return 0;
}
```

### UBSan Environment Variables

```bash
# Print stack traces
UBSAN_OPTIONS=print_stacktrace=1

# Halt on error
UBSAN_OPTIONS=halt_on_error=1

# Suppress specific checks
UBSAN_OPTIONS=suppressions=ubsan_suppressions.txt
```

## 🔄 ThreadSanitizer (TSan)

### What It Detects

- Data races
- Deadlocks
- Thread leaks
- Unsafe use of pthread APIs

### Compilation

```bash
# GCC/Clang
gcc -fsanitize=thread -g -O1 program.c -o program -lpthread

# C++
g++ -fsanitize=thread -g -O1 program.cpp -o program -lpthread
```

### Example: Data Race

```c
#include <pthread.h>
#include <stdio.h>

int global = 0;

void *thread_func(void *arg) {
    global++;  // Data race!
    return NULL;
}

int main() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_func, NULL);
    pthread_create(&t2, NULL, thread_func, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("Global: %d\n", global);
    return 0;
}
```

**TSan Output:**
```
==================
WARNING: ThreadSanitizer: data race (pid=12345)
  Write of size 4 at 0x... by thread T1:
    #0 thread_func program.c:6
    
  Previous write of size 4 at 0x... by thread T2:
    #0 thread_func program.c:6
```

### Fixed Version

```c
#include <pthread.h>
#include <stdio.h>

int global = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *thread_func(void *arg) {
    pthread_mutex_lock(&mutex);
    global++;  // Protected by mutex
    pthread_mutex_unlock(&mutex);
    return NULL;
}
```

### TSan Environment Variables

```bash
# Detailed reports
TSAN_OPTIONS=verbosity=1

# Second deadlock detection
TSAN_OPTIONS=second_deadlock_stack=1

# History size
TSAN_OPTIONS=history_size=7

# Custom suppressions
TSAN_OPTIONS=suppressions=tsan_suppressions.txt
```

## 💧 LeakSanitizer (LSan)

### What It Detects

- Memory leaks
- Detects blocks that are unreachable at program exit

### Usage

```bash
# Included with ASan
gcc -fsanitize=address program.c -o program

# Standalone (faster)
gcc -fsanitize=leak program.c -o program
```

### Example

```c
#include <stdlib.h>

int main() {
    int *leak = malloc(100);
    // Never freed!
    return 0;
}
```

**LSan Output:**
```
=================================================================
==12345==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 100 byte(s) in 1 object(s) allocated from:
    #0 0x... in malloc
    #1 0x... in main program.c:4
```

### LSan Environment Variables

```bash
# Disable leak detection
ASAN_OPTIONS=detect_leaks=0

# Leak check at specific point
__lsan_do_leak_check()  // In code

# Suppression file
LSAN_OPTIONS=suppressions=lsan_suppressions.txt
```

## 🔗 Combining Sanitizers

### Compatible Combinations

```bash
# ASan + UBSan (recommended)
gcc -fsanitize=address,undefined -g program.c -o program

# ASan + LSan (automatic)
gcc -fsanitize=address -g program.c -o program

# MSan + UBSan
clang -fsanitize=memory,undefined -g program.c -o program
```

### Incompatible Combinations

```
❌ ASan + TSan (cannot combine)
❌ MSan + TSan (cannot combine)
❌ ASan + MSan (cannot combine)
```

### Testing Strategy

```bash
# Build 1: ASan + UBSan + LSan
gcc -fsanitize=address,undefined -g -O1 program.c -o program_asan

# Build 2: MSan
clang -fsanitize=memory -fsanitize-memory-track-origins -g -O1 program.c -o program_msan

# Build 3: TSan (for multi-threaded code)
gcc -fsanitize=thread -g -O1 program.c -o program_tsan

# Run all versions
./program_asan
./program_msan
./program_tsan
```

## 🔧 Practical Examples

### Complete Makefile

```makefile
CC = clang
CFLAGS = -Wall -Wextra -g -O1

# Different sanitizer builds
all: program_asan program_msan program_tsan program_ubsan

program_asan: program.c
	$(CC) $(CFLAGS) -fsanitize=address,undefined program.c -o $@

program_msan: program.c
	$(CC) $(CFLAGS) -fsanitize=memory -fsanitize-memory-track-origins program.c -o $@

program_tsan: program.c
	$(CC) $(CFLAGS) -fsanitize=thread program.c -o $@ -lpthread

program_ubsan: program.c
	$(CC) $(CFLAGS) -fsanitize=undefined program.c -o $@

clean:
	rm -f program_asan program_msan program_tsan program_ubsan

test: all
	@echo "Testing with ASan..."
	./program_asan
	@echo "Testing with MSan..."
	./program_msan
	@echo "Testing with TSan..."
	./program_tsan
	@echo "Testing with UBSan..."
	./program_ubsan
```

### Suppression File Example

```bash
# lsan_suppressions.txt
# Suppress known leaks in third-party libraries
leak:libcrypto
leak:libssl

# Suppress specific function
leak:known_leak_function
```

**Usage:**
```bash
LSAN_OPTIONS=suppressions=lsan_suppressions.txt ./program
```

## 🚀 CI/CD Integration

### GitHub Actions Example

```yaml
name: Sanitizers

on: [push, pull_request]

jobs:
  sanitizers:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Install dependencies
      run: sudo apt-get update && sudo apt-get install -y clang
    
    - name: Build with ASan
      run: |
        clang -fsanitize=address,undefined -g -O1 program.c -o program_asan
    
    - name: Run ASan tests
      run: ./program_asan
      env:
        ASAN_OPTIONS: check_initialization_order=1:detect_stack_use_after_return=1
    
    - name: Build with MSan
      run: |
        clang -fsanitize=memory -fsanitize-memory-track-origins -g -O1 program.c -o program_msan
    
    - name: Run MSan tests
      run: ./program_msan
```

### GitLab CI Example

```yaml
stages:
  - test

sanitizer_tests:
  stage: test
  image: ubuntu:latest
  
  before_script:
    - apt-get update && apt-get install -y clang make
  
  script:
    - make program_asan
    - ASAN_OPTIONS=check_initialization_order=1 ./program_asan
    - make program_msan
    - ./program_msan
```

## 📚 Best Practices

### Development Workflow

1. **During Development:**
   ```bash
   # Use ASan + UBSan for daily development
   gcc -fsanitize=address,undefined -g -O1 program.c -o program
   ```

2. **Before Commit:**
   ```bash
   # Run all sanitizers
   make test_sanitizers
   ```

3. **In CI/CD:**
   ```bash
   # Automated sanitizer tests on every commit
   ```

### Performance Tips

- Use `-O1` or `-O2` optimization for faster sanitizer builds
- Don't use sanitizers in production builds
- Run different sanitizers separately for best performance
- Use `-fno-omit-frame-pointer` for better stack traces

### Common Pitfalls

```bash
# ❌ Don't mix incompatible sanitizers
gcc -fsanitize=address,thread  # Won't work!

# ✅ Run separately
gcc -fsanitize=address
gcc -fsanitize=thread

# ❌ Don't ignore sanitizer warnings
# ✅ Fix all issues before merging

# ❌ Don't disable sanitizers in tests
# ✅ Use suppressions for known issues only
```

## 📚 Resources

- [AddressSanitizer Documentation](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [MemorySanitizer Documentation](https://github.com/google/sanitizers/wiki/MemorySanitizer)
- [ThreadSanitizer Documentation](https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual)
- [UndefinedBehaviorSanitizer Documentation](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

---

**Pro Tip**: Always run your tests with sanitizers enabled. They catch bugs that traditional testing misses!
