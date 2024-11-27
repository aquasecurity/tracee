#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void* thread_func(void* arg) {
    // Try triggering a false posivie
    getpid();

    return NULL;
}

int main() {
    // Start a thread that will call getpid(), in an attempt to trigger a false positive
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }

    // Sleep a bit to have give potential false positives a chance to show themselves
    sleep(15);

    // Allocate a block of memory on the heap
    void *heap_memory = malloc(1024);
    if (heap_memory == NULL) {
        perror("malloc failed");
        return 1;
    }

    // Set stack pointer to the allocated heap memory (top of the block)
    void *new_sp = heap_memory + 1024;
#if defined(__x86_64__)
    __asm__ volatile (
        "mov %0, %%rsp\n"
        :
        : "r"(new_sp)
    );
#elif defined(__aarch64__)
    __asm__ volatile (
        "mov sp, %0\n"
        :
        : "r"(new_sp)
    );
#else
    #error "Unsupported architecture"
#endif

    // Trigger the stack pivot event by invoking exit_group() while the stack pointer is pointing to the heap
    exit(0);
}