# System Programming & POSIX Cheatsheet

Quick reference for system programming, POSIX APIs, and secure coding practices.

## 📚 Table of Contents

- [File Operations](#file-operations)
- [Process Management](#process-management)
- [Inter-Process Communication (IPC)](#inter-process-communication-ipc)
- [Memory Management](#memory-management)
- [Signals](#signals)
- [Network Programming](#network-programming)
- [Security Considerations](#security-considerations)

## 📄 File Operations

### Basic File I/O

```c
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// Open file
int fd = open("file.txt", O_RDONLY);
if (fd == -1) {
    perror("open");
    exit(1);
}

// Read
char buffer[1024];
ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
if (bytes_read == -1) {
    perror("read");
}
buffer[bytes_read] = '\0';

// Write
int fd_out = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
ssize_t bytes_written = write(fd_out, buffer, bytes_read);

// Close
close(fd);
close(fd_out);
```

### File Flags

```c
// Open modes
O_RDONLY    // Read only
O_WRONLY    // Write only
O_RDWR      // Read and write
O_APPEND    // Append mode
O_CREAT     // Create if not exists
O_TRUNC     // Truncate to zero length
O_EXCL      // Fail if file exists (with O_CREAT)
O_NONBLOCK  // Non-blocking mode

// Example: Create exclusive file
int fd = open("file.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
```

### File Permissions

```c
#include <sys/stat.h>

// Check if file exists
struct stat st;
if (stat("file.txt", &st) == 0) {
    printf("File exists\n");
    printf("Size: %ld bytes\n", st.st_size);
    printf("Mode: %o\n", st.st_mode & 0777);
}

// Change permissions
chmod("file.txt", 0644);  // rw-r--r--

// Change ownership
chown("file.txt", uid, gid);
```

### Directory Operations

```c
#include <dirent.h>
#include <sys/stat.h>

// List directory contents
DIR *dir = opendir(".");
if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        printf("%s\n", entry->d_name);
    }
    closedir(dir);
}

// Create directory
mkdir("newdir", 0755);

// Remove directory
rmdir("newdir");
```

## 🔄 Process Management

### Fork and Exec

```c
#include <unistd.h>
#include <sys/wait.h>

// Create child process
pid_t pid = fork();

if (pid == -1) {
    perror("fork");
    exit(1);
} else if (pid == 0) {
    // Child process
    printf("Child PID: %d\n", getpid());
    execlp("ls", "ls", "-l", NULL);
    perror("execlp");  // Only reached if exec fails
    exit(1);
} else {
    // Parent process
    printf("Parent PID: %d, Child PID: %d\n", getpid(), pid);
    
    // Wait for child
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status)) {
        printf("Child exited with status %d\n", WEXITSTATUS(status));
    }
}
```

### Process Information

```c
#include <unistd.h>
#include <sys/types.h>

// Get process IDs
pid_t pid = getpid();         // Current process ID
pid_t ppid = getppid();       // Parent process ID
uid_t uid = getuid();         // Real user ID
uid_t euid = geteuid();       // Effective user ID
gid_t gid = getgid();         // Real group ID
```

### System Calls

```c
// Execute shell command
int ret = system("ls -l");

// Better: Use fork + exec for security
pid_t pid = fork();
if (pid == 0) {
    char *args[] = {"ls", "-l", NULL};
    execvp(args[0], args);
    exit(1);
}
```

## 📡 Inter-Process Communication (IPC)

### Pipes

```c
#include <unistd.h>

int pipefd[2];
pipe(pipefd);  // pipefd[0] = read, pipefd[1] = write

pid_t pid = fork();
if (pid == 0) {
    // Child: writer
    close(pipefd[0]);  // Close read end
    write(pipefd[1], "Hello from child", 16);
    close(pipefd[1]);
    exit(0);
} else {
    // Parent: reader
    close(pipefd[1]);  // Close write end
    char buffer[100];
    ssize_t n = read(pipefd[0], buffer, sizeof(buffer));
    buffer[n] = '\0';
    printf("Received: %s\n", buffer);
    close(pipefd[0]);
    wait(NULL);
}
```

### Named Pipes (FIFOs)

```c
#include <sys/stat.h>
#include <fcntl.h>

// Create named pipe
mkfifo("/tmp/myfifo", 0666);

// Writer
int fd = open("/tmp/myfifo", O_WRONLY);
write(fd, "Hello", 5);
close(fd);

// Reader (in different process)
int fd = open("/tmp/myfifo", O_RDONLY);
char buffer[100];
read(fd, buffer, sizeof(buffer));
close(fd);
```

### Shared Memory

```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

// Create/open shared memory object
int shm_fd = shm_open("/myshm", O_CREAT | O_RDWR, 0666);

// Set size
ftruncate(shm_fd, 4096);

// Map to process memory
void *ptr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

// Write
sprintf(ptr, "Hello from shared memory");

// Read (in different process)
int shm_fd2 = shm_open("/myshm", O_RDONLY, 0666);
void *ptr2 = mmap(0, 4096, PROT_READ, MAP_SHARED, shm_fd2, 0);
printf("Read: %s\n", (char *)ptr2);

// Cleanup
munmap(ptr, 4096);
shm_unlink("/myshm");
```

### Message Queues

```c
#include <mqueue.h>

// Open/create message queue
struct mq_attr attr = {
    .mq_flags = 0,
    .mq_maxmsg = 10,
    .mq_msgsize = 256,
    .mq_curmsgs = 0
};

mqd_t mq = mq_open("/mymq", O_CREAT | O_RDWR, 0666, &attr);

// Send message
char *msg = "Hello";
mq_send(mq, msg, strlen(msg), 0);

// Receive message
char buffer[256];
unsigned int prio;
mq_receive(mq, buffer, 256, &prio);

// Cleanup
mq_close(mq);
mq_unlink("/mymq");
```

## 💾 Memory Management

### Dynamic Memory Allocation

```c
#include <stdlib.h>
#include <string.h>

// Allocate memory
int *arr = malloc(10 * sizeof(int));
if (!arr) {
    perror("malloc");
    exit(1);
}

// Initialize to zero
memset(arr, 0, 10 * sizeof(int));
// Or use calloc
int *arr2 = calloc(10, sizeof(int));

// Resize
arr = realloc(arr, 20 * sizeof(int));

// Free memory
free(arr);
free(arr2);
```

### Memory Mapping

```c
#include <sys/mman.h>

// Map file to memory
int fd = open("largefile.dat", O_RDONLY);
size_t size = 1024 * 1024;  // 1 MB

void *addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
if (addr == MAP_FAILED) {
    perror("mmap");
    exit(1);
}

// Access memory-mapped file
char *data = (char *)addr;
printf("First byte: %c\n", data[0]);

// Unmap
munmap(addr, size);
close(fd);
```

### Secure Memory

```c
#include <string.h>

// Avoid leaving sensitive data in memory
void secure_zero(void *s, size_t n) {
    volatile unsigned char *p = s;
    while (n--) *p++ = 0;
}

// Use with passwords, keys
char password[100];
// ... use password ...
secure_zero(password, sizeof(password));

// Or use explicit_bzero (if available)
explicit_bzero(password, sizeof(password));
```

## ⚡ Signals

### Signal Handling

```c
#include <signal.h>
#include <unistd.h>

// Signal handler
void sigint_handler(int sig) {
    printf("\nCaught signal %d (SIGINT)\n", sig);
    // Cleanup and exit
    exit(0);
}

int main() {
    // Register signal handler
    signal(SIGINT, sigint_handler);
    
    // Or use sigaction (more robust)
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    // Keep running
    while (1) {
        printf("Running... (Ctrl+C to stop)\n");
        sleep(1);
    }
    
    return 0;
}
```

### Common Signals

```c
SIGINT   // Interrupt (Ctrl+C)
SIGTERM  // Termination request
SIGKILL  // Kill (cannot be caught)
SIGSEGV  // Segmentation fault
SIGCHLD  // Child process terminated
SIGALRM  // Alarm clock
SIGUSR1  // User-defined signal 1
SIGUSR2  // User-defined signal 2
```

### Sending Signals

```c
#include <signal.h>

// Send signal to process
kill(pid, SIGTERM);

// Send to current process
raise(SIGTERM);

// Set alarm
alarm(5);  // SIGALRM in 5 seconds
```

## 🌐 Network Programming

### TCP Server

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int server_fd = socket(AF_INET, SOCK_STREAM, 0);

// Reuse address
int opt = 1;
setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

// Bind
struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = INADDR_ANY,
    .sin_port = htons(8080)
};
bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));

// Listen
listen(server_fd, 5);

// Accept connections
while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    
    // Handle client
    char buffer[1024];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    buffer[n] = '\0';
    printf("Received: %s\n", buffer);
    
    write(client_fd, "OK\n", 3);
    close(client_fd);
}
```

### TCP Client

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);

struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(8080)
};
inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

// Connect
if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("connect");
    exit(1);
}

// Send/receive
write(sock, "Hello", 5);
char buffer[1024];
read(sock, buffer, sizeof(buffer));

close(sock);
```

## 🔒 Security Considerations

### Input Validation

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// BAD: Buffer overflow
void bad_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Dangerous!
}

// GOOD: Bounds checking
void good_input(const char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

// BETTER: Use safer functions
void better_input(const char *user_input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", user_input);
}
```

### Path Traversal Prevention

```c
#include <limits.h>
#include <stdlib.h>

int is_safe_path(const char *path, const char *base) {
    char real[PATH_MAX];
    char base_real[PATH_MAX];
    
    // Resolve to absolute paths
    if (!realpath(path, real) || !realpath(base, base_real)) {
        return 0;
    }
    
    // Check if path starts with base
    return strncmp(real, base_real, strlen(base_real)) == 0;
}
```

### Privilege Management

```c
#include <unistd.h>
#include <sys/types.h>

// Drop privileges permanently
void drop_privileges(uid_t uid, gid_t gid) {
    // Drop group privileges
    if (setgid(gid) != 0) {
        perror("setgid");
        exit(1);
    }
    
    // Drop user privileges
    if (setuid(uid) != 0) {
        perror("setuid");
        exit(1);
    }
    
    // Verify we can't regain privileges
    if (setuid(0) != -1) {
        fprintf(stderr, "Failed to drop privileges!\n");
        exit(1);
    }
}
```

### Race Conditions (TOCTOU)

```c
// BAD: Time-of-check to time-of-use race
if (access("file.txt", W_OK) == 0) {
    // File could be changed here!
    int fd = open("file.txt", O_WRONLY);
}

// GOOD: Open directly and check
int fd = open("file.txt", O_WRONLY);
if (fd != -1) {
    // File is now locked, safe to use
    // ...
    close(fd);
}
```

### Safe String Functions

```c
// Unsafe functions (avoid these):
gets()      // Use fgets()
strcpy()    // Use strncpy() or strlcpy()
strcat()    // Use strncat() or strlcat()
sprintf()   // Use snprintf()

// Safe alternatives:
char buffer[100];

// fgets instead of gets
fgets(buffer, sizeof(buffer), stdin);

// snprintf instead of sprintf
snprintf(buffer, sizeof(buffer), "Value: %d", value);

// strncat instead of strcat
strncat(dest, src, sizeof(dest) - strlen(dest) - 1);
```

## 📚 Best Practices

### Error Handling

```c
#include <errno.h>
#include <string.h>

// Always check return values
int fd = open("file.txt", O_RDONLY);
if (fd == -1) {
    fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
    return 1;
}

// Check allocation
void *ptr = malloc(size);
if (!ptr) {
    perror("malloc");
    return 1;
}
```

### Resource Cleanup

```c
// Use RAII pattern or explicit cleanup

FILE *fp = fopen("file.txt", "r");
if (!fp) {
    return 1;
}

// Do work...

// Always clean up
fclose(fp);

// Or use goto for cleanup
error_cleanup:
    if (fp) fclose(fp);
    if (buffer) free(buffer);
    return error_code;
```

## 📚 Resources

- [POSIX Standard](https://pubs.opengroup.org/onlinepubs/9699919799/)
- [Linux Programming Interface](http://man7.org/tlpi/)
- [Advanced Programming in the UNIX Environment](https://www.apuebook.com/)

---

**Remember**: Always validate inputs, check return values, and follow the principle of least privilege!
