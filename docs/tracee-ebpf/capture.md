# Capturing Artifacts

Tracee has a unique feature that lets you capture interesting artifacts from running applications, using the `--capture` flag.

All captured artifacts are saved in Tracee's "output directory" which can be configured using `--capture dir:/path/to/dir`.

Tracee can capture the following types of artifacts:

1. Written files: Anytime a file is being written to, the contents of the file will be captured. Written files can be filtered using an optional path prefix.
2. Executed files: Anytime a binary is being executed, the binary file will be captured. If the same binary is executed multiple times, it will be captured just once.
3. Memory files: Anytime a "memory unpacker" is detected, the suspicious memory region will be captured. This is triggered when memory protection changes from Write+Execute to Write.

## CLI Options

CLI Option | Description
--- | ---
`[artifact:]write[=/path/prefix*]` | capture written files. A filter can be given to only capture file writes whose path starts with some prefix (up to 50 characters). Up to 3 filters can be given.
`[artifact:]exec` | capture executed files.
`[artifact:]mem` | capture memory regions that had write+execute (w+x) protection, and then changed to execute (x) only.
`[artifact:]all` | capture all of the above artifacts.
`dir:/path/to/dir` | path where tracee will save produced artifacts. the artifact will be saved into an 'out' subdirectory. (default: /tmp/tracee).
`clear-dir` | clear the captured artifacts output dir before starting (default: false).

(Use this flag multiple times to choose multiple capture options)

## Examples

Capture executed files into the default output directory

```
--capture exec
```

Delete /my/dir/out and then capture all supported artifacts into it

```
--capture all --capture dir:/my/dir --capture clear-dir
```

Capture files that were written into anywhere under `/usr/bin/` or `/etc/`

```
--capture write=/usr/bin/* --capture write=/etc/* 
```

