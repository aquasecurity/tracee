#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#define WATCH_PATH "/tmp/inotify_file"

void ensure_watch_path_exists() {
    struct stat st;
    if (stat(WATCH_PATH, &st) == -1) {
        FILE *file = fopen(WATCH_PATH, "w");
        if (!file) {
            perror("Failed to create WATCH_PATH");
            exit(1);
        }
        fclose(file);
        printf("Created %s\n", WATCH_PATH);
    }
}

void trigger_inotify() {
    int inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        perror("inotify_init");
        return;
    }

    int wd = inotify_add_watch(inotify_fd, WATCH_PATH, IN_MODIFY | IN_CREATE | IN_DELETE);
    if (wd == -1) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return;
    }

    printf("inotify_add_watch triggered security_path_notify\n");
    close(inotify_fd);
}

void trigger_fanotify() {
    int fanotify_fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fanotify_fd == -1) {
        perror("fanotify_init");
        return;
    }

    int ret = fanotify_mark(fanotify_fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, WATCH_PATH);
    if (ret == -1) {
        perror("fanotify_mark");
        close(fanotify_fd);
        return;
    }

    printf("fanotify_mark triggered security_path_notify\n");
    close(fanotify_fd);
}

int main() {
    ensure_watch_path_exists();

    printf("Triggering security_path_notify using inotify and fanotify...\n");

    trigger_inotify();
    trigger_fanotify();

    printf("Done.\n");
    return 0;
}
