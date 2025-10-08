section .data
    msg: db "Hello World!", 10, 0
    msg_len equ $ - msg - 1

section .text
    global start

start:
    mov rcx, 3                  ; Set counter to 3

top:
    push rcx                    ; put counter on stack

    ; macOS system call for write
    mov rax, 0x2000004         ; sys_write system call number for macOS
    mov rdi, 2                 ; File descriptor 2 - stderr
    mov rsi, msg               ; Memory address of message
    mov rdx, msg_len           ; The length of message
    syscall                    ; Call the kernel

    pop rcx                    ; Restore counter from the stack
    dec rcx                    ; Decrease counter
    jnz top                    ; If counter is not 0, jump to top

    ; Exit system call for macOS
    mov rax, 0x2000001         ; sys_exit system call number for macOS
    mov rdi, 0                 ; Exit with return code of 0
    syscall                    ; Call the kernel