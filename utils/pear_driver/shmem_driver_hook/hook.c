#include <stdint.h>
#include "hook.h"

#define kMaxAflInputSize (1 * 1024 * 1024)

// Shared memory hook to call before LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
void __pear_sharedmem_hook(struct x86_64_regs *regs, uint8_t *input_buf, uint32_t input_buf_len) {
    // Set arg 1 to testcase buffer
    regs->rdi = (uint64_t) input_buf;

    // Set arg 2 to testcase size.
    regs->rsi = input_buf_len;
}
