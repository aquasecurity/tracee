// gcc -o syscall_source_tester -z execstack syscall_source_tester.c

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

// execve("/bin/sh", ["/bin/sh", "-c", "exit"], NULL);
#if defined(__x86_64__)
#define SHELLCODE \
    "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00"  /* mov rax, 0x68732f6e69622f ; "/bin/sh\0" */ \
    "\x50"                                      /* push rax */ \
    "\x48\x89\xe7"                              /* mov rdi, rsp */ \
    "\x48\xc7\xc0\x2d\x63\x00\x00"              /* mov rax, 0x632d ; "-c\0" */ \
    "\x50"                                      /* push rax */ \
    "\x48\x89\xe3"                              /* mov rbx, rsp */ \
    "\x48\xc7\xc0\x65\x78\x69\x74"              /* mov rax, 0x74697865 ; "exit\0" */ \
    "\x50"                                      /* push rax */ \
    "\x48\x89\xe1"                              /* mov rcx, rsp */ \
    "\x48\x31\xc0"                              /* xor rax, rax */ \
    "\x50"                                      /* push rax */ \
    "\x51"                                      /* push rcx */ \
    "\x53"                                      /* push rbx */ \
    "\x57"                                      /* push rdi */ \
    "\x48\x89\xe6"                              /* mov rsi, rsp */ \
    "\x48\x89\xc2"                              /* mov rdx, rax */ \
    "\x48\xc7\xc0\x3b\x00\x00\x00"              /* mov rax, 59 ; __NR_execve */ \
    "\x0f\x05"                                  /* syscall */
#elif defined(__aarch64__)
#define SHELLCODE \
    "\xe3\x45\x8c\xd2" /* mov  x3, #0x622F */ \
    "\x23\xcd\xad\xf2" /* movk x3, #0x6E69, lsl #16 */ \
    "\xe3\x65\xce\xf2" /* movk x3, #0x732F, lsl #32 */ \
    "\x03\x0d\xe0\xf2" /* movk x3, #0x68, lsl #48 ; x3 = "/bin/sh\0" */ \
    "\xe3\x8f\x1f\xf8" /* str  x3, [sp, #-8]! */ \
    "\xe0\x03\x00\x91" /* mov x0, sp */ \
    "\xa3\x65\x8c\xd2" /* mov x3, #0x632d ; x3 = "-c\0" */ \
    "\xe3\x8f\x1f\xf8" /* str  x3, [sp, #-8]! */ \
    "\xe4\x03\x00\x91" /* mov x4, sp */ \
    "\xa3\x0c\x8f\xd2" /* mov x3, #0x7865 */ \
    "\x23\x8d\xae\xf2" /* movk x3, #0x7469, lsl#16 ; x3 = "exit\0" */ \
    "\xe3\x8f\x1f\xf8" /* str  x3, [sp, #-8]! */ \
    "\xe5\x03\x00\x91" /* mov x5, sp */ \
    "\xe3\x03\x1f\xaa" /* mov  x3, xzr */ \
    "\xe3\x8f\x1f\xf8" /* str x3, [sp, #-8]! */ \
    "\xe5\x8f\x1f\xf8" /* str x5, [sp, #-8]! */ \
    "\xe4\x8f\x1f\xf8" /* str x4, [sp, #-8]! */ \
    "\xe0\x8f\x1f\xf8" /* str x0, [sp, #-8]! */ \
    "\xe1\x03\x00\x91" /* mov x1, sp */ \
    "\xe2\x03\x03\xaa" /* mov x2, x3 */ \
    "\xa8\x1b\x80\xd2" /* mov  x8, #221 ; __NR_execve */ \
    "\x01\x00\x00\xd4" /* svc #0 */
#else
#error Invalid architecture
#endif

char shellcode[] = SHELLCODE;

int main(int argc, char *argv[])
{
    if (argc != 2) {
	printf("usage: ./syscall_source_tester [stack|heap|mmap]\n");
        goto fail;
    }
    
    if (strcmp(argv[1], "stack") == 0) {
        char shellcode_stack[] = SHELLCODE;
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
        if (mprotect((void *)((unsigned long long)shellcode_heap & ~(sysconf(_SC_PAGE_SIZE) - 1)), sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            perror("mprotect failed");
            goto fail;
        }

        // jump to the shellcode
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
        ((void (*)(void))shellcode_mmap)();

        // cannot be reached
        goto fail;
    }

fail:
    exit(EXIT_FAILURE);
}
