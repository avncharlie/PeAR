#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_func(char *buf) {
    printf("got: %s\n", buf);

    if (buf[0] == 'f') {
        printf("one\n");
        if (buf[1] == 'o') {
            printf("two\n");
            if (buf[2] == 'o') {
                printf("three\n");
                if (buf[3] == '!') {
                    printf("four\n");
                    if (buf[4] == '!') {
                        printf("five\n");
                        if (buf[5] == '!') {
                            printf("six\n");
                            int *b = 0;
                            *b = 5; // deliberate crash
                        }
                    }
                }
            }
        }
    }
}

void read_and_test_file(char *fname) {
    char buf[100];
    memset(buf, 0, sizeof buf);

    FILE *file = fopen(fname, "rb");
    if (!file) {
        perror("Error opening file");
        exit(2);
    }
    fread(buf, 1, sizeof buf, file);
    fclose(file);

    test_func(buf);
}
