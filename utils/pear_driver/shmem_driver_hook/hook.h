#include <stdint.h>

struct __attribute__((__packed__)) x86_64_regs {

    uint64_t rax, rbx, rcx, rdx, rdi, rsi, 
           r8, r9, r10, r11, r12, r13, r14, r15;

    uint8_t xmm_regs[16][16];
};
