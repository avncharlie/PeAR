#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Declare LLVMFuzzerTestOneInput. This is the function we need to pass input to.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

#define kMaxAflInputSize (1 * 1024 * 1024)
static uint8_t AflInputBuf[kMaxAflInputSize];

// Get testcase from stdin and execute
// This will be the target func for persistent mode (no shmem)
void __attribute__((noinline)) pear_driver_stdin_input(void) {
  size_t l = read(0, AflInputBuf, kMaxAflInputSize);
  LLVMFuzzerTestOneInput(AflInputBuf, l);
}

// On startup, init then fuzz
// If persistent mode will trigger a loop around pear_driver_stdin_input
int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  pear_driver_stdin_input();
  return 0;
}
