#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    // Program to execute
    char *program = "/bin/ls";
    char *args[] = { "ls", "-l", NULL };
    char *env[] = { NULL };

    if (execve(program, args, env) == -1) {
        perror("execve failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}
