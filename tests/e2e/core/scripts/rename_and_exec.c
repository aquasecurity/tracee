// Test program to verify prev_comm is correctly captured after task rename
// Compiles with: gcc -o rename_and_exec rename_and_exec.c

#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <new_name> <program_to_exec> [args...]\n", argv[0]);
        return 1;
    }

    const char *new_name = argv[1];
    const char *exec_prog = argv[2];

    // Rename this process
    if (prctl(PR_SET_NAME, new_name, 0, 0, 0) != 0) {
        perror("prctl PR_SET_NAME failed");
        return 1;
    }

    // Execute the target program
    // Pass remaining arguments to the exec'd program
    execvp(exec_prog, &argv[2]);

    // If exec fails
    perror("execvp failed");
    return 1;
}

