
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/types.h>

#define MEMORY_SIZE (16 * 1024 * 1024)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("Page size");
        return 1;
    }

    size_t pages = MEMORY_SIZE / (size_t)page_size;

    unsigned char *memory = mmap(NULL, MEMORY_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (memory == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Initialize every page before fork()
    for (size_t i = 0; i < pages; i++)
        memory[i * page_size] = 42;

    printf("=== Copy-on-Write Memory Demonstrator ===\n");
    printf("Page size: %ld bytes\n", page_size);
    printf("Memory allocated: %d MiB\n", 16);
    printf("Pages initialized: %zu\n", pages);
    printf("Original value: %d\n", memory[0]);

    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        munmap(memory, MEMORY_SIZE);
        return 1;
    }

    if (pid == 0) {
        printf("\n[CHILD PROCESS]\n");
        printf("Child PID: %d\n", getpid());
        printf("Parent PID: %d\n", getppid());
        printf("Value before modification: %d\n", memory[0]);

        getrusage(RUSAGE_SELF, &before);

        // Write to one byte on each page.
        // This normally triggers COW for these private pages.
        for (size_t i = 0; i < pages; i++)
            memory[i * page_size] = 99;

        getrusage(RUSAGE_SELF, &after);

        printf("Value after modification: %d\n", memory[0]);
        printf("Child minor faults during writes: %ld\n",
               after.ru_minflt - before.ru_minflt);
        printf("Child changed %zu page locations.\n", pages);
        printf("Child exits.\n");

        munmap(memory, MEMORY_SIZE);
        _exit(0);
    } else {
        printf("\n[PARENT PROCESS]\n");
        printf("Parent PID: %d\n", getpid());
        printf("Child PID: %d\n", pid);

        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            munmap(memory, MEMORY_SIZE);
            return 1;
        }

        getrusage(RUSAGE_SELF, &after);

        printf("\n[FINAL VERIFICATION]\n");
        printf("Parent value: %d\n", memory[0]);
        printf("Expected parent value: 42\n");
        printf("Parent data preserved: %s\n",
               memory[0] == 42 ? "YES" : "NO");
        printf("Parent minor faults since fork: %ld\n",
               after.ru_minflt - before.ru_minflt);
        printf("Child exited normally: %s\n",
               WIFEXITED(status) ? "YES" : "NO");

        munmap(memory, MEMORY_SIZE);
    }

    return 0;
}
