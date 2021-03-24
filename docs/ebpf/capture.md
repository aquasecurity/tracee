Tracee has a unique feature that lets you capture interesting artifacts from running applications, using the `--capture` flag.

All captured artifacts are saved in Tracee's "output directory" which can be configured using `--capture dir:/path/to/dir`.

Tracee can capture the following types of artifacts:

1. Written files: Anytime a file is being written to, the contents of the file will be captured. Written files can be filtered using an optional path prefix.
2. Executed files: Anytime a binary is being executed, the binary file will be captured. If the same binary is executed multiple times, it will be captured just once.
3. Memory files: Anytime a "memory unpacker" is detected, the suspicious memory region will be captured. This is triggered when memory protection changes from Write+Execute to Write.

To use, `--capture exec`, `--capture mem`, and `--capture write` capture executed, memory, and written files respectively. 
To filter written files, add a prefix expression like so: `--capture write=/etc/*`. This will capture anything written blow `/etc/`.

For a complete list of capture options, run `--capture help`.
