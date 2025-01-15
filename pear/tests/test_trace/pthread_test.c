#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void* print_one(void* arg) {
    printf("one\n");
    return 0;
}

void* print_two(void* arg) {
    printf("two\n");
    return 0;
}

int main() {
    pthread_t thread1, thread2;
    if (pthread_create(&thread1, NULL, print_one, NULL) != 0) {
        perror("Failed to create thread1");
        return 1;
    }
    if (pthread_create(&thread2, NULL, print_two, NULL) != 0) {
        perror("Failed to create thread2");
        return 1;
    }
    // Wait for both threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    return 0;
}
