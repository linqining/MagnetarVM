static const char message[] = "Hello, MagnetarVM!\n";

static long syscall3(long number, long a0, long a1, long a2) {
    register long x10 asm("a0") = a0;
    register long x11 asm("a1") = a1;
    register long x12 asm("a2") = a2;
    register long x17 asm("a7") = number;
    asm volatile("ecall" : "+r"(x10) : "r"(x11), "r"(x12), "r"(x17) : "memory");
    return x10;
}

__attribute__((noreturn)) void main(void) {
    syscall3(64, 1, (long)message, sizeof(message) - 1);
    syscall3(93, 0, 0, 0);
    __builtin_unreachable();
}
