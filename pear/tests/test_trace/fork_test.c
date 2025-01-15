#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

void print_one() {
    printf("one\n");
}

void print_two() {
    printf("two\n");
}

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Failed to fork process");
        return 1;
    } else if (pid == 0) {
        print_one();
    } else {
        print_two();
        waitpid(pid, NULL, 0);
    }

    return 0;
}
