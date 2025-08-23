#include <stdio.h>
#include <string.h>

// test data relocation
extern int foo;

// test external function 
extern void changeFoo(void);

int main() {
    char x[100];

    memset(x, 0, 100);
    snprintf(x, 100, "foo is: %d\n", foo);
    fwrite(x, 100, 1, stdout);
    changeFoo();
    memset(x, 0, 100);
    snprintf(x, 100, "foo is: %d\n", foo);
    fwrite(x, 100, 1, stdout);

    return 0;
}
