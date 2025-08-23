#include <stdio.h>
#include <stdlib.h>

extern void __cdecl read_and_test_file(char *);  // prototype only

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    read_and_test_file(argv[1]);
    return 0;
}

