#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hook.h"

void __pear_sharedmem_hook(struct x86_64_regs *regs, uint8_t *input_buf, uint32_t input_buf_len) {

    // reset buffer
    memset(regs->rdi, 0, 100);

    // ensure we don't overflow buffer
    if (input_buf_len > 100)
        input_buf_len = 100;

    // copy in test case
    memcpy(regs->rdi, input_buf, input_buf_len);
}
