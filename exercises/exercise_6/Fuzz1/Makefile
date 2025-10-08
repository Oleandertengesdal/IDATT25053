CC = clang
CXX = clang++
CFLAGS = -g -O1 -fsanitize=fuzzer,address -fsanitize-coverage=trace-pc-guard
TARGET = fuzz_string

all: $(TARGET)

$(TARGET): fuzz_string.c
	$(CXX) $(CFLAGS) fuzz_string.c -o $(TARGET)

# Run fuzzer for 60 seconds
fuzz: $(TARGET)
	./$(TARGET) -max_total_time=60 -print_final_stats=1

# Run with corpus directory
fuzz_corpus: $(TARGET)
	mkdir -p corpus
	./$(TARGET) corpus/ -max_total_time=60 -print_final_stats=1

# Clean build artifacts
clean:
	rm -f $(TARGET)
	rm -rf corpus/

# Test with a known crashing input (if you find one)
test_crash: $(TARGET)
	echo -n "Test input here" | ./$(TARGET)

.PHONY: all fuzz fuzz_corpus clean test_crash