#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wait.h>

extern int pthread_setname_np (pthread_t __target_thread, const char *__name);

// This is a test program that creates a process that creates 2 threads + 1 thread.
// It also executes itself again a few times (depending on the TIMES environment variable).
// This creates an exponential tree of processes and threads.
// All processes and threads remain running for a while, allowing the process tree to be inspected.

short time_to_sleep_in_secs = 60; // time that the threads sleep in seconds
short times_to_execute;           // number of times this test should be executed
char *full, *base;                // full path and base name of the executable

// Print functions

pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

void mprintf(FILE *stream, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    pthread_mutex_lock(&m);
    vfprintf(stream, format, args);
    pthread_mutex_unlock(&m);
    va_end(args);
}

#define print_info(...) { mprintf(stdout, __VA_ARGS__); }
#define print_error_exit(...) { mprintf(stderr, __VA_ARGS__); exit(1); }
#define print_perror_ret(...) { mprintf(stderr, __VA_ARGS__); perror(""); return -1; }
#define print_perror_ret_null(...) { mprintf(stderr, __VA_ARGS__); perror(""); return NULL; }
#define print_perror_void(...) { mprintf(stderr, __VA_ARGS__); perror(""); }

// Messages

char *thread_finished = "Thread (ppid=%d, pid=%d, tid=%d) finished.\n";
char *thread_started_creating = "Thread (ppid=%d, pid=%d, tid=%d) started. Creating another thread...\n";
char *thread_started_sleeping = "Thread (ppid=%d, pid=%d, tid=%d) started. Sleeping for %d seconds...\n";
char *child_started_sleeping = "Child (ppid=%d, pid=%d, tid=%d) started. Sleeping for %d seconds...\n";
char *child_finished = "Child (ppid=%d, pid=%d, tid=%d) finished.\n";
char *process_started = "Process (ppid=%d, pid=%d, tid=%d) started.\n";
char *process_finished = "Process (ppid=%d, pid=%d, tid=%d) finished.\n";
char *process_pid_finished = "Process (pid=%d) finished.\n";
char *times_to_execute_left = "TIMES to execute left: %d\n";
char *times_too_high = "TIMES is too high, setting it to 5.\n";
char *main_process_started = "Main process (ppid=%d, pid=%d, tid=%d) started.\n";

// Errors

char *err_creating_process = "Error creating process.\n";
char *err_creating_thread = "Error creating thread.\n";
char *err_joining = "Error joining thread.\n";
char *err_forking = "Error forking.\n";
char *err_execve = "Error executing command.\n";
char *err_env_var_not_set = "Environment variable TIMES not set.\n";
char *err_reading_proc_self_exe = "Error reading /proc/self/exe.\n";
char *err_waiting_for_process = "Error waiting for process.\n";

// Info

struct task_info {
    pid_t pid;
    pid_t tid;
    pid_t ppid;
};

struct task_info get_task_info(void)
{
    struct task_info info;
    info.pid = getpid();
    info.tid = syscall(SYS_gettid);
    info.ppid = getppid();
    return info;
}

// Threads

void *thread_sleeps_for_sometime(void *arg)
{
    pthread_setname_np(pthread_self(), "sleeping");
    struct task_info info = get_task_info();

    print_info(thread_started_sleeping, info.ppid, info.pid, info.tid, time_to_sleep_in_secs);

    sleep(time_to_sleep_in_secs);

    print_info(thread_finished, info.ppid, info.pid, info.tid);

    return NULL;
}

void *thread_creates_another_thread(void *arg)
{
    pthread_setname_np(pthread_self(), "another");
    struct task_info info = get_task_info();

    pthread_t thread;

    print_info(thread_started_creating, info.ppid, info.pid, info.tid);

    if (pthread_create(&thread, NULL, thread_sleeps_for_sometime, NULL))
        print_perror_void(err_creating_thread);

    if (pthread_join(thread, NULL))
        print_perror_void(err_joining);

    print_info(thread_finished, info.ppid, info.pid, info.tid);

    return NULL;
}

// Processes

#define number_of_threads 2

int process_spawning_sleep_threads(void)
{
    prctl(PR_SET_NAME, "spawning", 0, 0, 0);
    struct task_info info = get_task_info();

    pthread_t threads[number_of_threads];

    print_info(process_started, info.ppid, info.pid, info.tid);

    void *(*thread_functions[number_of_threads])(void *) = {
      thread_sleeps_for_sometime,
      thread_creates_another_thread
    };

    for (int i = 0; i < number_of_threads; i++) {
        if (pthread_create(&threads[i], NULL, thread_functions[i], NULL))
            print_perror_ret(err_creating_thread);
    }

    // Wait for all threads to finish
    for (int i = 0; i < number_of_threads; i++) {
        if (pthread_join(threads[i], NULL))
            print_perror_ret(err_joining);
    }

    print_info(process_finished, info.ppid, info.pid, info.tid);

    return 0;
}

#define minus_size 20

int process_execing_same_binary_again(void)
{
    prctl(PR_SET_NAME, "executing", 0, 0, 0);
    struct task_info info = get_task_info();

    char minus[minus_size] = {0};
    snprintf(minus, minus_size, "TIMES=%d", times_to_execute - 1);

    print_info(child_started_sleeping, info.ppid, info.pid, info.tid, time_to_sleep_in_secs);

    char *const argv[] = {base, NULL};
    char *const envp[] = {"PATH=/bin:/usr/bin", minus, NULL};

    if (execve(full, argv, envp) == -1)
        print_perror_ret(err_execve);

    // process is gone for good

    return 0;
}

// Support functions

char *get_exe_full_path(void)
{
    char *path = malloc(100);

    int len = readlink("/proc/self/exe", path, 100);
    if (len == -1) {
        free(path);
        print_perror_ret_null(err_reading_proc_self_exe)
    }

    path[len] = '\0';

    return path;
}

char *basename(char *path)
{
    char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

void set_times_to_execute(void)
{
    char *times = getenv("TIMES"); // WARNING: growth is exponential, so don't set this too high

    if ((times = getenv("TIMES")) == NULL)
        print_error_exit(err_env_var_not_set);

    // If environment var tells there are no more tests to execute, just sleep here and exit.

    if ((times_to_execute = atoi(times)) == 0) {
        prctl(PR_SET_NAME, "no-more-tests", 0, 0, 0);
        sleep(time_to_sleep_in_secs); // keep process alive togethe with all others
        exit(0);
    }

    // Watchout for a fork bomb =D
    if (times_to_execute > 5) {
        print_info(times_too_high);
        times_to_execute = 5;
    }
}

// Main

int main()
{
    prctl(PR_SET_NAME, "proctree", 0, 0, 0);
    struct task_info info = get_task_info();

    print_info(main_process_started, info.ppid, info.pid, info.tid);

    pid_t one, two;

    full = get_exe_full_path();
    base = basename(full);

    set_times_to_execute();

    print_info(times_to_execute_left, times_to_execute);

    // Set process name

    char procname[16] = {0};
    snprintf(procname, 16, "tester-%d", times_to_execute);
    prctl(PR_SET_NAME, procname, 0, 0, 0);

    // Local threads: 1 process, 2 threads + 1 thread (created by one of the 2 threads)

    switch ((one = fork())) {
        case -1:
            print_error_exit(err_forking);
        case 0:
            if (process_spawning_sleep_threads())
                print_error_exit(err_creating_process);
    }

    // The amount of childs (executing this process again) is times_to_execute

    if (one > 0) {
        for (int i = 0; i < times_to_execute; i++) {
            switch (fork()) {
                case -1:
                    print_error_exit(err_forking);
                case 0:
                    if (process_execing_same_binary_again())
                        print_error_exit(err_execve);
            }
        }

        // Wait for all childs to finish

        int status, wpid;

        while ((wpid = (int) waitpid(-1, &status, 0)) > 0)
            print_info(process_pid_finished, wpid);

        if (errno != ECHILD)
            print_perror_ret(err_waiting_for_process);
    }

    return 0;
}
