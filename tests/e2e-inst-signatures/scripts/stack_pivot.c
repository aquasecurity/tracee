#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void *thread_func(void *arg)
{
    // Try triggering a false positive
    getpid();

    return NULL;
}

int main()
{
    // Start a thread that will call getpid(), in an attempt to trigger a false positive
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }

    // Sleep a bit to have give potential false positives a chance to show themselves
    char *sleep_env = getenv("E2E_INST_TEST_SLEEP");
    int sleep_time = sleep_env ? atoi(sleep_env) : 5; // default to 5 if not set
    sleep(sleep_time);

    // Allocate memory from the main heap (brk) to avoid mmap-based arenas
    void *heap_memory = sbrk(0);
    if (heap_memory == (void *) -1) {
        perror("sbrk failed");
        return 1;
    }
    if (sbrk(1024) == (void *) -1) {
        perror("sbrk failed");
        return 1;
    }

    // Set stack pointer to the allocated heap memory (top of the block)
    void *new_sp = (char *) heap_memory + 1024;
#if defined(__x86_64__)
    __asm__ volatile("mov %0, %%rsp\n" : : "r"(new_sp));
#elif defined(__aarch64__)
    __asm__ volatile("mov sp, %0\n" : : "r"(new_sp));
#else
    #error "Unsupported architecture"
#endif

    // Trigger the stack pivot event by invoking exit_group() while the stack pointer
    // is pointing to the heap.
    exit(0);
}
