// tree_tester.c — helper for the `tree` scope-filter integration test.
//
// Prints "READY <pid>" and then waits for SIGUSR1. On SIGUSR1 it forks a child that execs
// `sleep`, so the descendant is spawned AFTER tracee has already started — this exercises
// fork-time process-tree membership propagation (not just the initial procfs seeding).
//
// Build: gcc -o tree_tester tree_tester.c
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t got_signal = 0;

static void handler(int sig)
{
    (void) sig;
    got_signal = 1;
}

int main(void)
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("READY %d\n", (int) getpid());

    // Wait until the test (after starting tracee with a tree=<this pid> policy) signals us.
    while (!got_signal)
        pause();

    pid_t child = fork();
    if (child == 0) {
        // Descendant of this process; its exec/exit should follow the tree membership.
        execlp("sleep", "sleep", "30", (char *) NULL);
        _exit(127);
    }
    printf("SPAWNED %d\n", (int) child);

    // Stay alive so the subtree persists while tracee collects events.
    sleep(30);
    return 0;
}
