#include <stdint.h>
#include <string.h>
#include "hook.h"

#define kMaxAflInputSize (1 * 1024 * 1024)

// Shared memory hook to call before LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
void __pear_sharedmem_hook(struct x86_64_regs *regs, uint8_t *input_buf, uint32_t input_buf_len) {
    // Arg 1 (pointer to the buffer) is in rdi. So we memset this pointer to
    // clear existing input.
    // Ensure we don't overflow buffer
    if (input_buf_len > kMaxAflInputSize)
        input_buf_len = kMaxAflInputSize;
    // Copy in AFL++'s generated test case.
    memcpy(regs->rdi, input_buf, input_buf_len);

    // Arg 2 (in rsi) is testcase size.
    regs->rsi = input_buf_len;
}
