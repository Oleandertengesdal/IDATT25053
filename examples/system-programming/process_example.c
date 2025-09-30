/*
 * Process Management Example
 * 
 * Demonstrates fork(), exec(), and wait() system calls
 * Shows proper process creation and synchronization
 * 
 * Compile: gcc process_example.c -o process_example
 * Run: ./process_example
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>

void example_basic_fork() {
    printf("\n=== Example 1: Basic Fork ===\n");
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // Child process
        printf("Child process: PID=%d, Parent PID=%d\n", getpid(), getppid());
        sleep(1);
        printf("Child: Exiting...\n");
        exit(0);
    } else {
        // Parent process
        printf("Parent process: PID=%d, Child PID=%d\n", getpid(), pid);
        
        // Wait for child to finish
        int status;
        pid_t child_pid = wait(&status);
        
        if (WIFEXITED(status)) {
            printf("Parent: Child %d exited with status %d\n", 
                   child_pid, WEXITSTATUS(status));
        }
    }
}

void example_exec() {
    printf("\n=== Example 2: Fork and Exec ===\n");
    
    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // Child process - execute 'ls -l'
        printf("Child: Executing 'ls -l'\n");
        char *args[] = {"ls", "-l", NULL};
        execvp(args[0], args);
        
        // execvp only returns on error
        perror("execvp failed");
        exit(1);
    } else {
        // Parent waits for child
        int status;
        waitpid(pid, &status, 0);
        printf("Parent: Child completed\n");
    }
}

void example_multiple_children() {
    printf("\n=== Example 3: Multiple Children ===\n");
    
    const int NUM_CHILDREN = 3;
    pid_t children[NUM_CHILDREN];
    
    // Create multiple child processes
    for (int i = 0; i < NUM_CHILDREN; i++) {
        pid_t pid = fork();
        
        if (pid == -1) {
            perror("fork failed");
            exit(1);
        } else if (pid == 0) {
            // Child process
            printf("Child %d: PID=%d, sleeping for %d seconds\n", 
                   i, getpid(), i + 1);
            sleep(i + 1);
            printf("Child %d: Done!\n", i);
            exit(i);  // Exit with unique status
        } else {
            // Parent stores child PID
            children[i] = pid;
        }
    }
    
    // Parent waits for all children
    printf("Parent: Waiting for all children...\n");
    for (int i = 0; i < NUM_CHILDREN; i++) {
        int status;
        pid_t pid = waitpid(children[i], &status, 0);
        
        if (WIFEXITED(status)) {
            printf("Parent: Child %d (PID=%d) exited with status %d\n",
                   i, pid, WEXITSTATUS(status));
        }
    }
    printf("Parent: All children completed\n");
}

void example_process_info() {
    printf("\n=== Example 4: Process Information ===\n");
    
    printf("Process ID (PID):        %d\n", getpid());
    printf("Parent Process ID (PPID): %d\n", getppid());
    printf("User ID (UID):           %d\n", getuid());
    printf("Effective UID:           %d\n", geteuid());
    printf("Group ID (GID):          %d\n", getgid());
    printf("Effective GID:           %d\n", getegid());
}

int main() {
    printf("=== POSIX Process Management Examples ===\n");
    
    // Run examples
    example_basic_fork();
    example_exec();
    example_multiple_children();
    example_process_info();
    
    printf("\n=== All examples completed ===\n");
    return 0;
}

/*
 * Key Concepts:
 * 
 * 1. fork() creates a copy of the current process
 *    - Returns 0 in child, child's PID in parent
 *    - Returns -1 on error
 * 
 * 2. exec() family replaces current process image
 *    - execvp() searches PATH for executable
 *    - Only returns on error
 * 
 * 3. wait() family waits for child processes
 *    - wait() waits for any child
 *    - waitpid() waits for specific child
 *    - Status contains exit code and termination info
 * 
 * 4. Common patterns:
 *    - Fork-exec: Create child and run different program
 *    - Fork-wait: Create children and synchronize
 *    - Process pools: Create multiple workers
 * 
 * Security Notes:
 * - Always check fork() return value
 * - Always wait() for children to prevent zombies
 * - Validate input before exec()
 * - Be careful with setuid programs
 */
