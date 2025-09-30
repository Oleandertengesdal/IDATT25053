# System Programming Examples

This directory contains examples demonstrating POSIX APIs and secure system programming.

## Examples

### 1. Process Management (`process_example.c`)
Demonstrates fork, exec, and wait operations.

**Topics:**
- Creating child processes
- Process synchronization
- Exit status handling

**Compilation & Running:**
```bash
gcc process_example.c -o process_example
./process_example
```

### 2. Pipe Communication (`pipe_example.c`)
Inter-process communication using pipes.

**Topics:**
- Creating pipes
- Parent-child communication
- Bidirectional communication

**Compilation & Running:**
```bash
gcc pipe_example.c -o pipe_example
./pipe_example
```

### 3. Signal Handling (`signal_example.c`)
Safe signal handling with sigaction.

**Topics:**
- Registering signal handlers
- Handling SIGINT, SIGTERM
- Cleanup on signals

**Compilation & Running:**
```bash
gcc signal_example.c -o signal_example
./signal_example
# Press Ctrl+C to test SIGINT handling
```

### 4. Secure File Operations (`secure_file.c`)
Demonstrates secure file handling.

**Topics:**
- Safe file permissions
- Avoiding race conditions (TOCTOU)
- Secure temporary files

**Compilation & Running:**
```bash
gcc secure_file.c -o secure_file
./secure_file
```

### 5. Network Server (`tcp_server.c`)
Simple TCP echo server.

**Topics:**
- Socket creation
- Binding and listening
- Handling multiple clients (with fork)

**Compilation & Running:**
```bash
gcc tcp_server.c -o tcp_server
./tcp_server 8080

# In another terminal:
nc localhost 8080
```

## Requirements

- GCC compiler
- Linux/Unix system (or WSL on Windows)
- Standard C library

## Security Considerations

All examples demonstrate:
- Input validation
- Error checking
- Resource cleanup
- Secure coding practices

## Common Security Pitfalls Addressed

1. **Buffer Overflows** - Using safe string functions
2. **Race Conditions** - Avoiding TOCTOU bugs
3. **Resource Leaks** - Proper cleanup in error paths
4. **Privilege Management** - Dropping privileges when needed
5. **Signal Safety** - Using async-signal-safe functions

## Testing

```bash
# Compile all examples
make all

# Run with sanitizers
gcc -fsanitize=address,undefined process_example.c -o process_example
./process_example

# Check with Valgrind
valgrind --leak-check=full ./process_example
```

## Resources

- [Linux Programming Interface](http://man7.org/tlpi/)
- [POSIX.1-2017 Standard](https://pubs.opengroup.org/onlinepubs/9699919799/)
- [Secure Coding in C/C++](https://www.securecoding.cert.org/)

---

**Note**: These examples prioritize clarity and educational value. Production code should include more robust error handling and logging.
