#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>

int main()
{
    // Open or create a file
    int fd = open("vfs_writev.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Prepare the messages to write
    char *message1 = "This is message 1.\n";
    char *message2 = "This is message 2.\n";
    char *message3 = "This is message 3.\n";

    // Create iov structures for each message
    struct iovec iov[3];
    iov[0].iov_base = message1;
    iov[0].iov_len = strlen(message1);
    iov[1].iov_base = message2;
    iov[1].iov_len = strlen(message2);
    iov[2].iov_base = message3;
    iov[2].iov_len = strlen(message3);

    // Write to the file using writev syscall
    ssize_t bytes_written = writev(fd, iov, 3);
    if (bytes_written == -1) {
        perror("writev");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Total bytes written: %zd\n", bytes_written);

    // Close the file
    close(fd);

    return 0;
}
