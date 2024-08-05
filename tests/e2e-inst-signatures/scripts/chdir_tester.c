#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    // Change current working directory using chdir
    if (chdir("./test_link") == -1) {
        perror("Failed to change directory");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}