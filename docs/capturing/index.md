# Getting Started with Capturing

!!! Note
    This entire section is about running **tracee-ebpf** only, without piping
    events to **tracee-rules** but, instead, **capturing artifacts** from
    the environment being traced.

Tracee has a unique feature that lets you capture interesting artifacts from
running applications, using the `--capture` flag.

```text
$ sudo ./dist/tracee-ebpf --capture help
$ sudo ./dist/tracee-ebpf --capture xxx
```
!!! Tip
    All captured artifacts are saved in Tracee's "output directory", which can
    be configured using `--capture dir:/path/to/dir`. You may also use
    `--capture clear-dir` if you want contents of the destination directory
    to be cleared every time you execute tracee.

## Artifacts Types

Tracee can capture the following types of artifacts:

1. **Written Files**

     Anytime a file is being written to, the contents of the file
     will be captured. Written files can be filtered using an optional path
     prefix.

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output json \
        --trace comm=bash \
        --trace follow \
        --output option:parse-arguments \
        --capture dir:/tmp/tracee/ \
        --capture write=/tmp/*

     $ echo testing 123 > /tmp/testing.txt
     ```

     ```json
     {"timestamp":1657321167356748797,"threadStartTime":620311624458929,"processorId":7,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":6,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/tmp/testing.txt"},{"name":"flags","type":"string","value":"O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":1966101},{"name":"ctime","type":"unsigned long","value":1657321027326584850},{"name":"syscall_pathname","type":"const char*","value":"/tmp/testing.txt"}]}
     {"timestamp":1657321167356729582,"threadStartTime":620311624458929,"processorId":7,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/tmp/testing.txt"},{"name":"flags","type":"string","value":"O_WRONLY|O_CREAT|O_TRUNC"},{"name":"mode","type":"mode_t","value":438}]}
     ```

    !!! Note
        You can read captured files written at `/tmp/tracee/out`:
        ```text
        $ sudo cat /tmp/tracee/out/host/write.dev-271581185.inode-1966101
        testing 123
        ```

1. **Executed Files**

     Anytime a **binary is executed**, the binary file will be captured. If the
     same binary is executed multiple times, it will be captured just once.

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output json \
        --trace comm=bash \
        --trace follow \
        --output option:parse-arguments \
        --capture dir:/tmp/tracee/ \
        --capture exec
    
     $ /bin/ls
     ```

     ```json
     {"timestamp":1657322300531713371,"threadStartTime":620311624458929,"processorId":21,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"56","eventName":"clone","argsNum":5,"returnValue":3331757,"stackAddresses":null,"args":[{"name":"flags","type":"string","value":"CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID"},{"name":"stack","type":"void*","value":"0x0"},{"name":"parent_tid","type":"int*","value":"0x0"},{"name":"child_tid","type":"int*","value":"0x7fd7ce0d3a10"},{"name":"tls","type":"unsigned long","value":0}]}
     {"timestamp":1657322300534562489,"threadStartTime":620311624458929,"processorId":21,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"3","eventName":"close","argsNum":1,"returnValue":0,"stackAddresses":null,"args":[{"name":"fd","type":"int","value":3}]}
     ```

    !!! Note
        You will have a copy of each executed file written at `/tmp/tracee/out`:
        ```text
        $ ldd /bin/ls
        linux-vdso.so.1 (0x00007ffca632c000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f9a930d5000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a92ead000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f9a92e16000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9a93136000)

        $ ldd /tmp/tracee/out/host/exec.1657322052835478987.ls
        linux-vdso.so.1 (0x00007ffe337fb000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007feeb1fa5000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007feeb1d7d000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007feeb1ce6000)
        /lib64/ld-linux-x86-64.so.2 (0x00007feeb2006000)

        $ sudo chmod +x /tmp/tracee/out/host/exec.1657322052835478987.ls
        $ /tmp/tracee/out/host/exec.1657322052835478987.ls
        ```

1. **Memory Files**

     Anytime a **memory unpacker** is detected, the suspicious **memory region**
     will be captured. This is triggered when memory protection changes from
     **Write+Execute** to **Write**.

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output none \
        --trace comm=bash \
        --trace follow \
        --capture dir:/tmp/tracee/ \
        --capture mem
     ```

    !!! Note
        You may opt not to have any output from **tracee** with `--output none`
        command flag is given. This makes tracee to work in capture mode only.

1. **Network PCAP Files**

     Anytime a **packet** goes through the **network interface**, the **packet
     is captured into the pcap file**. Only packets that are generated by traced
     processes are being captured.

     A good way to test this behavior is to execute:

     ```text
     $ sudo ./dist/tracee-ebpf \
         --output format:json \
         --output option:parse-arguments \
         --output option:detect-syscall \
         -trace comm=ping \
         --capture net=lo
     ```

     and execute on the host:
     
     ```text
     $ ping 127.0.0.1
     ```
     
     and observe **pcap file**:
     
     ```text
     $ tcpdump -n -r /tmp/tracee/out/host/capture.pcap
     
     15:48:33.109392 IP 127.0.0.1 > 127.0.0.1: ICMP echo request, id 74, seq 1, length 64
     15:48:33.109440 IP 127.0.0.1 > 127.0.0.1: ICMP echo reply, id 74, seq 1, length 64
     15:48:34.138680 IP 127.0.0.1 > 127.0.0.1: ICMP echo request, id 74, seq 2, length 64
     15:48:34.138725 IP 127.0.0.1 > 127.0.0.1: ICMP echo reply, id 74, seq 2, length 64
     ```

     OR, **mix capture and tracing** options w/ different interfaces:

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output format:json \
        --output option:parse-arguments \
        --output option:detect-syscall \
        -trace comm=ping \
        -trace event=net_packet \
        -trace net=docker0 \
        --capture net=lo
     ```

    1. If user executes on the host:

        ```text
        $ ping 1.1.1.1
        ```

        it **won't be** captured into **pcap file** (since it won't go through
        lo).

    2. Now, if user executes on the host:

        ```text
        $ ping 127.0.0.1
        ```

        this **will be** captured into the **pcap file** (lo interface
        captured).

    3. If user executes in a container:

        ```text
        $ ping 127.0.0.1
        ```

        this **won't be** captured into **pcap file** (lo refers to the host
        only for now).

    4. Now, if user executes:

        ```text
        $ ping 1.1.1.1
        ```

        this **won't be** captured into **pcap file** (but it will be traced
        because command is tracing docker0 interface).

        !!! Attention
            For now **Tracee** only supports: **ETH**, **IP/IPv6** and 
            **ICMP/UDP/TCP** protocols.

1. **Loaded Kernel Modules**

     Anytime a **kernel module** is loaded, the binary file will be captured.
     If the same binary is loaded multiple times, it will be captured just once.

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output none \
        --trace comm=bash \
        --trace follow \
        --capture clear-dir \
        --capture module
     ```

     Captured module will be found in tracee destination directory, just like
     any other captured file would be:

     ```text
     $ sudo ls /tmp/tracee/out/host
       module.dev-271581185.inode-4071826.pid-3668786.c8b62228208f4bdbf21df09c01046b73dd44733841675bf3c0ff969fbedab616
     ```

     AND, the captured module is an exact copy of the loaded module:

     ```text
     $ sudo rmmod lkm_example
     $ sudo insmod /tmp/tracee/out/host/module.dev-271581185.inode-4071826.pid-3668786.c8b62228208f4bdbf21df09c01046b73dd44733841675bf3c0ff969fbedab616
     $ lsmod | grep example
     lkm_example            16384  0
     $ sudo rmmod lkm_example
     ```

     you can even load/unload it.

    !!! Note
        Example kernel module taken from [this blog]

[this blog]: https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234
