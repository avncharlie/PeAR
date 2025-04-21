#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Declare LLVMFuzzerTestOneInput. This is the function we need to pass input to.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

#define kMaxAflInputSize (1 * 1024 * 1024)
static uint8_t AflInputBuf[kMaxAflInputSize];

// On startup, init then fuzz
// Shmem hook will intercept LLVMFuzzerTestOneInput and populate with testcase
//   and length.
int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  LLVMFuzzerTestOneInput(AflInputBuf, 0);
  return 0;
}
