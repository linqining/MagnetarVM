    .section .text.entry
    .globl _start
_start:
    li sp, 0x10008000
    call main
    li a7, 93
    li a0, 0
    ecall
1:
    j 1b
