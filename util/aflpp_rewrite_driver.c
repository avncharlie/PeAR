#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

#define kMaxAflInputSize (1 * 1024 * 1024)
static uint8_t AflInputBuf[kMaxAflInputSize];

void __attribute__((noinline)) afl_rewrite_driver_stdin_input(void) {

  size_t l = read(0, AflInputBuf, kMaxAflInputSize);
  LLVMFuzzerTestOneInput(AflInputBuf, l);

}

int main(int argc, char **argv) {

  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);

  afl_rewrite_driver_stdin_input();

  return 0;

}

