#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hook.h"

void __pear_sharedmem_hook(struct x86_64_regs *regs, uint8_t *input_buf, uint32_t input_buf_len) {
    // This is an example shared memory hook designed to be called before a test
    // function that takes a buffer of size 100 as its first argument.

    // Arg 1 (pointer to the buffer) is in rdi. 
    // Ensure we don't overflow buffer
    if (input_buf_len > 100)
        input_buf_len = 100;

    // Now we copy in AFL++'s generated test case.
    memcpy(regs->rdi, input_buf, input_buf_len);
}
