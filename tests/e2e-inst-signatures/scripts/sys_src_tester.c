// gcc -o sys_src_tester -z execstack sys_src_tester.c

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

// exit(0);
#if defined(__x86_64__)
#define SHELLCODE \
    "\x48\x31\xFF"                 /* xor rdi, rdi */ \
    "\x48\xC7\xC0\x3C\x00\x00\x00" /* mov rax, 60 ; __NR_exit */ \
    "\x0F\x05"                     /* syscall */
#elif defined(__aarch64__)
#define SHELLCODE \
    "\x00\x00\x80\xD2" /* mov x0, 0 */ \
    "\xA8\x0B\x80\xD2" /* mov x8, #93 ; __NR_exit */ \
    "\x01\x00\x00\xD4" /* svc #0 */
#else
#error Invalid architecture
#endif

char shellcode[] = SHELLCODE;

void *thread_func(void *);

int main(int argc, char *argv[])
{
    if (argc != 2)
        goto usage;
    
    if (strcmp(argv[1], "stack") == 0) {
        char shellcode_stack[] = SHELLCODE;
#if defined(__aarch64__)
        __builtin___clear_cache (&shellcode_stack, &shellcode_stack + sizeof(shellcode));
#endif
        ((void (*)(void))shellcode_stack)();
        // cannot be reached
        goto fail;
    }

    if (strcmp(argv[1], "heap") == 0) {
        void *shellcode_heap = malloc(sizeof(shellcode));
        if (shellcode_heap == NULL) {
            perror("malloc failed");
            goto fail;
        }

        memcpy(shellcode_heap, shellcode, sizeof(shellcode));

        // set the heap memory as executable
        if (mprotect((void *)((unsigned long long)shellcode_heap & ~(sysconf(_SC_PAGE_SIZE) - 1)), 2 * sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            perror("mprotect failed");
            goto fail;
        }

        // jump to the shellcode
#if defined(__aarch64__)
        __builtin___clear_cache (&shellcode_heap, &shellcode_heap + sizeof(shellcode));
#endif
        ((void (*)(void))shellcode_heap)();

        // cannot be reached
        goto fail;
    }

    if (strcmp(argv[1], "mmap") == 0) {
        // create an anonymous mapping for the shellcode
        void *shellcode_mmap = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (shellcode_mmap == MAP_FAILED) {
            perror("mmap failed");
            goto fail;
        }

        memcpy(shellcode_mmap, shellcode, sizeof(shellcode));

        // jump to the shellcode
#if defined(__aarch64__)
        __builtin___clear_cache(&shellcode_mmap, &shellcode_mmap + sizeof(shellcode));
#endif
        ((void (*)(void))shellcode_mmap)();

        // cannot be reached
        goto fail;
    }

    if (strcmp(argv[1], "thread-stack") == 0) {
        // spawn a new thread which will run the shellcode from its stack
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_func, NULL) != 0) {
            perror("pthread_create failed");
            goto fail;
        }

        // wait for the new thread to exit
        if (pthread_join(thread, NULL) != 0) {
            perror("pthread_join failed");
            goto fail;
        }

        return 0;
    }

usage:
    printf("usage: ./sys_src_tester [stack|heap|mmap]\n");
fail:
    exit(EXIT_FAILURE);
}

void *thread_func(void *arg)
{
    // place the shellcode on the stack
    char shellcode_stack[] = SHELLCODE;

    // set the stack memory as executable
    if (mprotect((void *)((unsigned long long)shellcode_stack & ~(sysconf(_SC_PAGE_SIZE) - 1)), 2 * sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect failed");
        return NULL;
    }

    // jump to the shellcode
#if defined(__aarch64__)
    __builtin___clear_cache (&shellcode_stack, &shellcode_stack + sizeof(shellcode));
#endif
    ((void (*)(void))shellcode_stack)();

    // cannot be reached
    return NULL;
}
