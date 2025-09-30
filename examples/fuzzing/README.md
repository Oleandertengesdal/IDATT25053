# Fuzzing Examples

This directory contains examples demonstrating fuzzing techniques with different tools.

## Examples

### 1. LibFuzzer Example (`fuzz_target.cpp`)
A simple LibFuzzer target that demonstrates how to write a fuzz harness.

**Compilation:**
```bash
clang++ -g -fsanitize=fuzzer,address fuzz_target.cpp -o fuzzer
```

**Running:**
```bash
# Create corpus directory
mkdir corpus

# Run fuzzer
./fuzzer corpus/

# With options
./fuzzer corpus/ -max_len=256 -timeout=10
```

### 2. AFL Example (`afl_target.c`)
Example program for fuzzing with AFL/AFL++.

**Compilation:**
```bash
# With AFL++
afl-clang-fast afl_target.c -o afl_target

# Or with AFL
afl-gcc afl_target.c -o afl_target
```

**Running:**
```bash
# Create input directory
mkdir input
echo "test" > input/seed.txt

# Run AFL
afl-fuzz -i input -o findings -- ./afl_target @@
```

### 3. Vulnerable Parser (`vulnerable_parser.c`)
Intentionally vulnerable program for fuzzing practice.

**Contains vulnerabilities:**
- Buffer overflow
- Integer overflow
- Out-of-bounds read

**Compilation:**
```bash
# For AFL
afl-clang-fast vulnerable_parser.c -o vulnerable_parser

# For LibFuzzer
clang -fsanitize=fuzzer,address vulnerable_parser.c -o vulnerable_parser_fuzz
```

## Requirements

**For AFL/AFL++:**
```bash
# Install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

**For LibFuzzer:**
```bash
# Clang includes LibFuzzer
sudo apt install clang
```

## Tips

1. **Start with small corpus** - A few valid inputs work better than many
2. **Use dictionaries** - Speed up discovery of structured formats
3. **Enable sanitizers** - Catch more bugs (ASan, UBSan)
4. **Monitor coverage** - More coverage = better testing
5. **Minimize crashes** - Use `afl-tmin` to reduce crash cases

## ⚠️ Safety Warning

The vulnerable programs are for educational purposes only. Do not use them in production!

## Resources

- [LibFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus/tree/stable/docs)
- [Google OSS-Fuzz](https://github.com/google/oss-fuzz)
