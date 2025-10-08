# Compiler and flags
CC = clang
CXX = clang++
CFLAGS = -g -O1 -fno-omit-frame-pointer
ASAN_FLAGS = -fsanitize=address,fuzzer
NORMAL_FLAGS = -fsanitize=address

# Source files
IMPL_SRC = html_entities_impl.c
FUZZ_SRC = fuzz.c

# Output files
FUZZ_TARGET = fuzz_html_entities
NORMAL_TARGET = html_entities

# Default target
all: $(FUZZ_TARGET) $(NORMAL_TARGET)

# Build fuzzer with AddressSanitizer
$(FUZZ_TARGET): $(IMPL_SRC) $(FUZZ_SRC)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ $^

# Build normal executable with AddressSanitizer (for testing)
$(NORMAL_TARGET): $(IMPL_SRC)
	$(CC) $(CFLAGS) $(NORMAL_FLAGS) -o $@ $^

# Create corpus directory
corpus:
	mkdir -p corpus

# Create initial corpus with some test cases
init-corpus: corpus
	echo "Hello World" > corpus/test1.txt
	echo "&<>" > corpus/test2.txt
	echo "Test & test < test >" > corpus/test3.txt
	echo "" > corpus/test4.txt
	echo "&&&&" > corpus/test5.txt
	echo "<<<>>>" > corpus/test6.txt

# Run fuzzer
fuzz: $(FUZZ_TARGET) init-corpus
	./$(FUZZ_TARGET) corpus/ -max_total_time=60

# Run with more aggressive settings
fuzz-long: $(FUZZ_TARGET) init-corpus
	./$(FUZZ_TARGET) corpus/ -max_total_time=300 -max_len=1024

# Run normal program (for manual testing)
run: $(NORMAL_TARGET)
	./$(NORMAL_TARGET)

# Clean build artifacts
clean:
	rm -f $(FUZZ_TARGET) $(NORMAL_TARGET)
	rm -rf corpus/

# Clean everything including crash files
clean-all: clean
	rm -f crash-* leak-* timeout-*

.PHONY: all fuzz fuzz-long run clean clean-all corpus init-corpus