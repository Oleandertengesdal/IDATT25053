# Fuzzing Cheatsheet

Quick reference for fuzzing tools, techniques, and best practices.

## 📚 Table of Contents

- [Fuzzing Basics](#fuzzing-basics)
- [Coverage-Guided Fuzzing](#coverage-guided-fuzzing)
- [AFL & AFL++](#afl--afl)
- [LibFuzzer](#libfuzzer)
- [Binary Fuzzing](#binary-fuzzing)
- [Corpus Management](#corpus-management)
- [Fuzzing Best Practices](#fuzzing-best-practices)
- [Advanced Techniques](#advanced-techniques)

## 🎯 Fuzzing Basics

### What is Fuzzing?
Automated testing technique that provides invalid, unexpected, or random data as input to find bugs, crashes, and vulnerabilities.

### Types of Fuzzing

| Type | Description | Example |
|------|-------------|---------|
| **Mutation-based** | Mutate existing inputs | AFL, AFL++ |
| **Generation-based** | Generate inputs from scratch | Peach, Sulley |
| **Coverage-guided** | Uses code coverage feedback | AFL, LibFuzzer |
| **Blind/Black-box** | No feedback mechanism | Radamsa |

## 🔄 Coverage-Guided Fuzzing

### How It Works
1. Run program with input
2. Measure code coverage
3. If new coverage found, save input to corpus
4. Mutate interesting inputs
5. Repeat

### Why Coverage-Guided?
- Finds deeper bugs
- More efficient than random fuzzing
- Explores different code paths systematically

## 🐛 AFL & AFL++

### Installation

```bash
# AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install

# Or via package manager
sudo apt install afl++
```

### Basic Usage

**1. Compile Target with Instrumentation:**
```bash
# C/C++ compilation
afl-clang-fast -o target target.c
# Or
afl-gcc -o target target.c

# With sanitizers (recommended)
AFL_USE_ASAN=1 afl-clang-fast -o target target.c
```

**2. Prepare Seed Corpus:**
```bash
mkdir input_seeds
echo "test input" > input_seeds/seed1.txt
# Add more valid inputs
```

**3. Start Fuzzing:**
```bash
afl-fuzz -i input_seeds -o findings -- ./target @@
# @@ is replaced with input file path

# Multiple cores
afl-fuzz -i seeds -o out -M fuzzer01 -- ./target @@  # Master
afl-fuzz -i seeds -o out -S fuzzer02 -- ./target @@  # Slave
afl-fuzz -i seeds -o out -S fuzzer03 -- ./target @@  # Slave
```

**4. Reading from stdin:**
```bash
afl-fuzz -i seeds -o out -- ./target
# Program reads from stdin
```

### AFL++ Advanced Features

**Persistent Mode (faster):**
```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

while (__AFL_LOOP(1000)) {
  // Your code that processes input
  // Read input, process, return
}
```

**Deferred Forkserver:**
```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();  // Place after initialization
#endif
// Rest of your code
```

**Dictionary Support:**
```bash
# Create dictionary file
cat > dict.txt << EOF
keyword1="SQL"
keyword2="SELECT"
keyword3="INSERT"
EOF

afl-fuzz -i seeds -o out -x dict.txt -- ./target @@
```

### AFL Status Screen

```
Fuzzing status:
┌─ process timing ─────────────────────┐
│   run time : 0 days, 1 hrs, 23 min  │
│  last new path : 0 days, 0 hrs, 5 min│
│ last uniq crash : none               │
└──────────────────────────────────────┘

┌─ overall results ────────────────────┐
│   cycles done : 12                   │
│  total paths : 234                   │
│ uniq crashes : 3                     │
│  uniq hangs : 0                      │
└──────────────────────────────────────┘
```

**Key Metrics:**
- **cycles done**: Full queue scans completed
- **total paths**: Unique code paths found
- **uniq crashes**: Unique crashes discovered
- **stability**: Should be >90%

### AFL Environment Variables

```bash
# Core dumps
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# Skip CPU frequency check
export AFL_SKIP_CPUFREQ=1

# Custom mutator
export AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/mutator.so

# Use ASAN
export AFL_USE_ASAN=1

# Use MSAN
export AFL_USE_MSAN=1

# Increase memory limit
export AFL_MEM_LIMIT_MB=none
```

## 📚 LibFuzzer

### Installation
```bash
# LibFuzzer comes with Clang
# Ubuntu/Debian
sudo apt install clang

# Verify
clang --version
```

### Basic Fuzz Target

```cpp
// fuzz_target.cpp
#include <stdint.h>
#include <stddef.h>

// Fuzz target function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Your code to test
  if (Size >= 3) {
    if (Data[0] == 'F' && Data[1] == 'U' && Data[2] == 'Z') {
      // Bug: crash on "FUZ"
      __builtin_trap();
    }
  }
  return 0;  // Non-zero for invalid input
}
```

### Compilation & Running

```bash
# Compile with fuzzing instrumentation
clang++ -g -fsanitize=fuzzer,address fuzz_target.cpp -o fuzzer

# Run fuzzer
./fuzzer

# With corpus directory
./fuzzer corpus/

# With options
./fuzzer corpus/ -max_len=1024 -timeout=10 -runs=1000000

# With sanitizers
clang++ -g -fsanitize=fuzzer,address,undefined fuzz_target.cpp -o fuzzer
```

### LibFuzzer Options

```bash
# Time limit
./fuzzer -max_total_time=3600  # 1 hour

# Maximum input size
./fuzzer -max_len=4096

# Timeout per input
./fuzzer -timeout=10

# Number of runs
./fuzzer -runs=1000000

# Parallel jobs
./fuzzer -jobs=8 -workers=8

# Dictionary
./fuzzer -dict=keywords.txt

# Minimize crash
./fuzzer -minimize_crash=1 crash-file

# Merge corpora
./fuzzer -merge=1 new_corpus/ old_corpus/
```

### LibFuzzer with Structure-Aware Fuzzing

```cpp
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);
  
  // Consume different data types
  int num = fdp.ConsumeIntegral<int>();
  std::string str = fdp.ConsumeRandomLengthString(100);
  bool flag = fdp.ConsumeBool();
  
  // Test your function
  my_function(num, str, flag);
  
  return 0;
}
```

## 🔧 Binary Fuzzing

### QEMU Mode (Black-box Fuzzing)

```bash
# Build AFL with QEMU support
cd AFLplusplus
make
cd qemu_mode
./build_qemu_support.sh

# Fuzz binary without source code
afl-fuzz -Q -i seeds -o findings -- /path/to/binary @@
```

### Unicorn Mode (Fast Emulation)

```python
# Install Unicorn
pip install unicorn

# AFL Unicorn mode for specific functions
# Useful for fuzzing specific code regions
```

### Frida Mode (Dynamic Instrumentation)

```bash
# Instrument running applications
afl-fuzz -O -i seeds -o findings -- /path/to/binary
```

## 📦 Corpus Management

### Corpus Minimization

```bash
# AFL corpus minimization
afl-cmin -i input_corpus -o minimized_corpus -- ./target @@

# With memory limit
afl-cmin -m 512 -i input -o output -- ./target @@

# LibFuzzer corpus merge
./fuzzer -merge=1 new_corpus/ corpus1/ corpus2/
```

### Test Case Minimization

```bash
# AFL test case minimization
afl-tmin -i crash_file -o minimized_crash -- ./target @@

# LibFuzzer crash minimization
./fuzzer -minimize_crash=1 crash-file
```

### Corpus Distillation

```bash
# Reduce corpus to smallest set covering same code
afl-cmin -i large_corpus -o small_corpus -- ./target @@
```

## 🎯 Fuzzing Best Practices

### Effective Seed Selection

```bash
# Good seeds:
✅ Valid inputs that parse correctly
✅ Various formats (if applicable)
✅ Small file sizes (faster mutations)
✅ Edge cases (empty, maximum size)

# Bad seeds:
❌ Too large files (slow fuzzing)
❌ All similar inputs
❌ Random garbage
```

### Compilation Flags

```bash
# Debug build
-g

# Sanitizers (highly recommended)
-fsanitize=address           # AddressSanitizer (memory errors)
-fsanitize=undefined         # UndefinedBehaviorSanitizer
-fsanitize=memory            # MemorySanitizer (uninitialized reads)

# Fuzzing instrumentation
-fsanitize=fuzzer           # LibFuzzer
-fsanitize-coverage=trace-pc-guard  # Coverage

# Optimizations
-O1 or -O2  # Some optimization for speed
```

### Complete Compilation Example

```bash
# AFL++ with multiple sanitizers
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast++ \
  -g -O2 -fsanitize=address,undefined \
  target.cpp -o target

# LibFuzzer with sanitizers
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
  fuzz_target.cpp -o fuzzer
```

### Parallel Fuzzing

```bash
# AFL++ parallel fuzzing
#!/bin/bash
# Start master
tmux new-session -d -s fuzz 'afl-fuzz -i seeds -o sync -M master -- ./target @@'

# Start slaves
for i in {1..7}; do
  tmux new-window -t fuzz "afl-fuzz -i seeds -o sync -S slave$i -- ./target @@"
done

# Attach to session
tmux attach -t fuzz
```

## 🚀 Advanced Techniques

### Custom Mutators

```c
// custom_mutator.c
#include "afl-fuzz.h"

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
  // Custom mutation logic
  // Return mutated size
}
```

### Dictionaries

```txt
# keywords.dict
keyword_sql="SELECT"
keyword_sql2="INSERT"
keyword_sql3="DELETE"
keyword_html="<script>"
keyword_html2="</script>"
magic_num="\x89PNG"
```

### Fuzzing Network Services

```bash
# Use AFL with network input
# Create wrapper that reads from file and sends via network

# Example wrapper
#!/bin/bash
cat $1 | nc localhost 8080
```

### Continuous Fuzzing

```bash
# Run fuzzing continuously
while true; do
  afl-fuzz -i seeds -o out -- ./target @@
  # Analyze crashes
  # Restart with new findings
done
```

### Coverage Analysis

```bash
# Generate coverage report
afl-cov -d findings/ \
        --coverage-cmd "./target AFL_FILE" \
        --code-dir . \
        --coverage-include-lines

# View coverage with lcov
geninfo . -b . -o coverage.info
genhtml coverage.info -o coverage_html/
```

## 🔍 Analyzing Results

### Crash Triage

```bash
# List unique crashes
ls findings/crashes/

# Reproduce crash
./target < findings/crashes/id:000000...

# With debugger
gdb ./target
(gdb) run < findings/crashes/id:000000...

# Automatic crash analysis
exploitable crashes/id:000000...
```

### Crash Deduplication

```bash
# AFL-based
afl-collect -d findings/ -e gdb -- ./target @@

# Manual with stack hashes
for crash in findings/crashes/*; do
  gdb -batch -ex "run < $crash" -ex "bt" ./target 2>&1 | md5sum
done | sort -u
```

## 🛠️ Other Fuzzing Tools

### Honggfuzz
```bash
# Install
sudo apt install honggfuzz

# Run
honggfuzz -i input/ -o findings/ -- ./target ___FILE___
```

### Radamsa (Mutation Fuzzer)
```bash
# Install
sudo apt install radamsa

# Use
echo "test" | radamsa
radamsa sample.txt -n 100 -o fuzzed-%n.txt
```

### Boofuzz (Network Protocol Fuzzing)
```python
from boofuzz import *

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)))

s_initialize("HTTP")
s_string("GET", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("/")
s_delim(" ", fuzzable=False)
s_string("HTTP/1.1", fuzzable=False)

session.connect(s_get("HTTP"))
session.fuzz()
```

## 📊 Fuzzing Metrics

### Key Performance Indicators

```
exec/sec     - Executions per second (higher is better)
stability    - Input determinism (should be >90%)
bitmap       - Coverage map density
paths        - Unique code paths discovered
crashes      - Total unique crashes found
```

### Optimization Tips

1. **Increase exec/sec:**
   - Use persistent mode
   - Reduce input size
   - Optimize target code
   - Use deferred forkserver

2. **Improve coverage:**
   - Better seed corpus
   - Use dictionaries
   - Run longer
   - Multiple fuzzing strategies

## 📚 Resources

- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus/tree/stable/docs)
- [LibFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [Fuzzing Book](https://www.fuzzingbook.org/)
- [Google OSS-Fuzz](https://github.com/google/oss-fuzz)

---

**Pro Tip**: Start with LibFuzzer for new projects (easy to integrate). Use AFL++ for existing binaries or when you need advanced features.
