# Fuzzing HTML Entities Function with AddressSanitizer

This project demonstrates fuzzing a C function that replaces HTML special characters with their entity equivalents.

## Prerequisites

- `clang` compiler (required for fuzzing support)
- Linux or macOS (recommended)

## File Structure

```
.
├── html_entities_impl.c  # Main implementation with replace_html_entities()
├── fuzz.c                # Fuzzing harness with LLVMFuzzerTestOneInput()
├── Makefile              # Build configuration
└── README.md             # This file
```

## Building

### Build the fuzzer:
```bash
make fuzz_html_entities
```

### Build normal executable with AddressSanitizer:
```bash
make html_entities
```

### Build both:
```bash
make all
```

## Running the Fuzzer

### Quick fuzz (60 seconds):
```bash
make fuzz
```

### Longer fuzz session (5 minutes):
```bash
make fuzz-long
```

### Manual fuzzing with custom options:
```bash
./fuzz_html_entities corpus/ -max_total_time=120 -max_len=512
```

## Understanding the Output

### Normal fuzzing output shows:
- **#exec/s**: Executions per second
- **cov**: Code coverage (edges covered)
- **corpus**: Number of interesting inputs found

### If bugs are found:
- Crash files will be saved as `crash-<hash>`
- Leak files will be saved as `leak-<hash>`
- Timeout files will be saved as `timeout-<hash>`

### To reproduce a crash:
```bash
./fuzz_html_entities crash-<hash>
```

## Common Bugs to Look For

With AddressSanitizer, you might find:

1. **Buffer overflows**: Writing beyond allocated memory
2. **Heap-use-after-free**: Using freed memory
3. **Memory leaks**: Not freeing allocated memory
4. **Integer overflows**: In size calculations
5. **NULL pointer dereferences**: Missing NULL checks

## Example Bugs You Might Introduce

To test that fuzzing works, you could introduce bugs like:

### Buffer overflow:
```c
// Remove the size calculation and use a fixed small buffer
char* output = malloc(10);  // Too small!
```

### Off-by-one error:
```c
// Forget to add +1 for null terminator
char* output = malloc(new_len);  // Missing +1
```

### Integer overflow:
```c
// No check if new_len overflows
size_t new_len = len * 100;  // Could overflow with large input
```

## Cleaning Up

### Remove build artifacts:
```bash
make clean
```

### Remove everything including crash files:
```bash
make clean-all
```

## Testing the Normal Program

Run the normal program manually:
```bash
make run
```

Then enter test strings like:
- `Hello & goodbye`
- `<script>alert('xss')</script>`
- `Test & < > all`

## Expected Behavior

The function should:
- Replace `&` with `&amp;`
- Replace `<` with `&lt;`
- Replace `>` with `&gt;`
- Handle empty strings
- Handle strings with no special characters
- Handle multiple consecutive special characters

## Notes

- The fuzzer will create a `corpus/` directory with interesting test cases
- AddressSanitizer adds runtime overhead but catches memory errors
- The fuzzer uses coverage-guided testing to explore different code paths