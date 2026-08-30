#include<stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc, char **argv){
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename with full path to open.\n", argv[0]);
        return 1;
    }

    // printf("argc = %d\n", argc);
    // printf("program = %s\n", argv[0]);
    // printf("arg 1   = %s\n", argv[1]);

    int t = 1;
    while (t == 1){
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
            // printf("Unable to open file, no file descriptor returned\n"); // internally use write()
            return 1;
        }

        // printf("File Descriptor: %d\n", fd); // internally use write()

        struct stat st;
        int f = fstat(fd, &st);
        if(f < 0 ){
            // printf("Unable to get the file descriptor info\n"); // internally use write()
            return 1;
        }

        // printf("Total Size from fstat: %ld\n", st.st_size); // internally use write()
        char *buf = malloc(st.st_size + 1);
        if(!buf){
            // printf("Unable to allocate memory with size: %ld\n", st.st_size + 1); // internally use write()
            return 1;
        }
        ssize_t n = read(fd, buf, st.st_size); // use sizeof() for arbitrary size

        if (n < 0) {
            return 1;
        }

        buf[n] = '\0';
        // printf("Buf Bytes Returned: %ld\n", n); // internally use write()
        // printf("-- Start of data --\n"); // internally use write()
        // printf("%s\n", buf); // internally use write()
        // printf("-- End of data --\n"); // internally use write()
        close(fd);

        sleep(3);
    }
}