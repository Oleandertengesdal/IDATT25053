.section __DATA,__data
msg:
    .ascii "Hello World!\n"
msg_len = . - msg

.section __TEXT,__text
.global _main
.align 2

_main:
    mov w8, #3                  // Set counter to 3

loop:
    // Save counter on stack
    str w8, [sp, #-16]!
    
    // macOS system call for write (stderr)
    mov x16, #4                 // sys_write system call number
    mov x0, #2                  // File descriptor 2 - stderr
    adrp x1, msg@PAGE           // Get page address of message
    add x1, x1, msg@PAGEOFF     // Add page offset to get full address
    mov x2, msg_len             // The length of message
    svc #0x80                   // System call
    
    // Restore counter from stack
    ldr w8, [sp], #16
    subs w8, w8, #1             // Decrease counter and set flags
    b.ne loop                   // If counter is not 0, jump to loop
    
    // Exit system call
    mov x16, #1                 // sys_exit system call number
    mov x0, #0                  // Exit with return code of 0
    svc #0x80                   // System call