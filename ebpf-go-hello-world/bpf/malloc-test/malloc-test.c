#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) { // gcc malloc-test.c -o malloc-test | ./malloc-test 10485760
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bytes>\n", argv[0]);
        return 1;
    }

    size_t size = strtoull(argv[1], NULL, 10);

    void *p = malloc(size);
    if (!p) {
        perror("malloc");
        return 1;
    }

    printf("PID: %d\n", getpid());
    printf("Allocated: %zu bytes (%.2f MiB)\n",
           size,
           (double)size / (1024 * 1024));

    fflush(stdout);

    sleep(300);

    free(p);

    return 0;
}