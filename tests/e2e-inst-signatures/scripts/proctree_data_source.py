#!/usr/bin/env python3
import os
import subprocess
import threading
import time


# Should be long enough to allow all threads and processes to launch for the test, and for the
# test signature to end its logic
SLEEP_DURATION = 10


def log(message: str):
    tid = threading.get_native_id()
    pid = os.getpid()
    ppid = os.getppid()
    print(f"(pid={pid}, tid={tid}, ppid={ppid}) - {message}")


def worker_thread():
    log(f"Started worker. Sleeping for {SLEEP_DURATION} seconds...")
    time.sleep(SLEEP_DURATION)
    log("Worker thread finished sleeping.");


def special_worker_thread():
    log("Started special worker. Creating another thread...")
    worker = threading.Thread(target=worker_thread)
    worker.start()
    worker.join()
    log("Special worker thread finished.")


# Launch a bash process, which run the process triggering the test event.
# The 'ls' execution should trigger the test, and the ls should have the bash parent and python
# grandparent in the lineage, but the parent by the 'ls' execution should be modified to sleep.
# This way we can test multiple threads in the grandparent, and lineage vs real time info in the
# tree.
def launch_test_subprocesses():
    subprocess.run(['/bin/bash', '-c', f'bash -c \"sleep 2; ls"& exec sleep {SLEEP_DURATION}'], text=True)


def main():
    log(f"Started process.")

    # Create thread objects for both functions
    thread1 = threading.Thread(target=worker_thread)
    thread2 = threading.Thread(target=special_worker_thread)


    # Start the threads
    thread1.start()
    thread2.start()

    # Launch the test processes, triggering the signature
    launch_test_subprocesses()

    # Wait for both threads to finish
    thread1.join()
    thread2.join()

    log("All threads have finished.")


if __name__ == "__main__":
    main()

