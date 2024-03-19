#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/fanotify.h>

#define DNOTIFY_PATH "dnotify_test"
#define INOTIFY_PATH "inotify_test"
#define FANOTIFY_PATH "fanotify_test"

static void cleanup_and_exit(int exit_code)
{
    rmdir(DNOTIFY_PATH);
    rmdir(INOTIFY_PATH);
    rmdir(FANOTIFY_PATH);

    exit(exit_code);
}

static void mkdir_exist_ok(const char *path)
{
    errno = 0;
    int dir_result = mkdir(path, 0755);
    if (dir_result != 0 && errno != EEXIST) {
        perror("mkdir");
        cleanup_and_exit(EXIT_FAILURE);
    }
}

static void dnotify_watch(const char *path)
{
    int fd;
    const int NOTIFY_SIG = SIGRTMIN;
    int events = DN_ACCESS | DN_ATTRIB | DN_CREATE | DN_DELETE |
                    DN_MODIFY | DN_RENAME | DN_MULTISHOT;
    
    signal(NOTIFY_SIG, SIG_IGN);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        cleanup_and_exit(EXIT_FAILURE);
    }

    if (fcntl(fd, F_SETSIG, NOTIFY_SIG) == -1) {
        perror("fcntl: F_SETSIG");
        cleanup_and_exit(EXIT_FAILURE);
    }
    
    if (fcntl(fd, F_NOTIFY, events) == -1) {
        perror("fcntl: F_NOTIFY");
        cleanup_and_exit(EXIT_FAILURE);
    }
    
    close(fd);
}

static void inotify_watch(const char *path)
{
    int inotify_fd, watch_fd;

    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        cleanup_and_exit(EXIT_FAILURE);
    }

    watch_fd = inotify_add_watch(inotify_fd, path, IN_ALL_EVENTS);
    if (watch_fd < 0) {
        perror("inotify_add_watch");
        cleanup_and_exit(EXIT_FAILURE);
    }

    close(inotify_fd);
}

static void fanotify_watch(const char *path)
{
    int fanotify_fd, watch_fd;

    fanotify_fd = fanotify_init(FAN_CLOEXEC, O_RDONLY | O_LARGEFILE);
    if (fanotify_fd < 0) {
        perror("fanotify_init");
        cleanup_and_exit(EXIT_FAILURE);
    }

    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD,
            FAN_ALL_EVENTS, AT_FDCWD, path) < 0) {
        perror("fanotify_mark");
        cleanup_and_exit(EXIT_FAILURE);
    }

    close(fanotify_fd);
}

void main(void) {
    mkdir_exist_ok(DNOTIFY_PATH);
    dnotify_watch(DNOTIFY_PATH);

    mkdir_exist_ok(INOTIFY_PATH);
    inotify_watch(INOTIFY_PATH);

    mkdir_exist_ok(FANOTIFY_PATH);
    fanotify_watch(FANOTIFY_PATH);

    cleanup_and_exit(EXIT_SUCCESS);
}