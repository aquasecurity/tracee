# Getting Started with Forensics

Tracee has a unique feature that lets you capture interesting artifacts from
running applications, using the `--capture` flag.

```console
./dist/tracee man capture
```

```console
sudo ./dist/tracee --capture xxx
```

!!! Tip
    All captured artifacts are saved in Tracee's "output directory", which can
    be configured using `--capture dir:/path/to/dir`. You may also use
    `--capture clear-dir` if you want contents of the destination directory
    to be cleared every time you execute tracee.

## Artifacts Types

Tracee can capture the following types of artifacts:

1. **I/O Files**

    Anytime a file is being written to and/or read from, the contents of the
    file will be captured. I/O files can be filtered using 3 optional filters:
    1. path - prefix of the file written/read. Up to 3 path filters can be
       provided per capture type.
    2. type - file's type can be `pipe`, `socket`, `elf` or `regular`.
    3. fd - standard FD, one of the following: `stdin`, `stdout` and `stderr`.

    ***write example***
    ```console
    sudo ./dist/tracee \
       --output json \
       --scope comm=bash \
       --scope follow \
       --output option:parse-arguments \
       --capture dir:/tmp/tracee/ \
       --capture write='/tmp/*'
    ```
   
    !!! Note
        Using file capture without filter name will be path by default. Hence,
        `--capture write='/tmp/*` is the same as `--capture write:path='/tmp/*`.

    ```console
    echo write testing 123 > /tmp/testing.txt
    ```

    ```json
    {"timestamp":1657321167356748797,"threadStartTime":620311624458929,"processorId":7,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":6,"returnValue":0,"stackAddresses":null,"syscall":"openat","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/tmp/testing.txt"},{"name":"flags","type":"string","value":"O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":1966101},{"name":"ctime","type":"unsigned long","value":1657321027326584850},{"name":"syscall_pathname","type":"const char*","value":"/tmp/testing.txt"}]}
    {"timestamp":1657321167356729582,"threadStartTime":620311624458929,"processorId":7,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"syscall":"openat","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/tmp/testing.txt"},{"name":"flags","type":"string","value":"O_WRONLY|O_CREAT|O_TRUNC"},{"name":"mode","type":"mode_t","value":438}]}
    ```

    !!! Note
        You can read captured files written at `/tmp/tracee/out`:
        ```console
        sudo cat /tmp/tracee/out/host/write.dev-271581185.inode-1966101
        ```

        ```text
        write testing 123
        ```
    
    ***read example***

    ```console
    sudo ./dist/tracee \
       --output json \
       --scope comm=bash \
       --scope follow \
       --output option:parse-arguments \
       --capture dir:/tmp/tracee/ \
       --capture read:type=pipe \
       --capture read:fd=stdin'
    ```

    ```console
    echo read testing 123 | cat
    ```
   
    ```json
    {"timestamp":1685285181028166900,"threadStartTime":1685285181026565700,"processorId":1,"processId":182934,"cgroupId":1,"threadId":182934,"parentProcessId":147428,"hostProcessId":184128,"hostThreadId":184128,"hostParentProcessId":148293,"userId":0,"mountNamespace":4026532277,"pidNamespace":4026532279,"processName":"cat","hostName":"Alon-Zivony","container":{},"kubernetes":{},"eventId":"720","eventName":"vfs_read","matchedPolicies":[""],"argsNum":5,"returnValue":17,"syscall":"read","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":""},{"name":"dev","type":"dev_t","value":12},{"name":"inode","type":"unsigned long","value":174033},{"name":"count","type":"size_t","value":131072},{"name":"pos","type":"off_t","value":0}]}
    {"timestamp":1685285181028267200,"threadStartTime":1685285181026565700,"processorId":1,"processId":182934,"cgroupId":1,"threadId":182934,"parentProcessId":147428,"hostProcessId":184128,"hostThreadId":184128,"hostParentProcessId":148293,"userId":0,"mountNamespace":4026532277,"pidNamespace":4026532279,"processName":"cat","hostName":"Alon-Zivony","container":{},"kubernetes":{},"eventId":"720","eventName":"vfs_read","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"read","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":""},{"name":"dev","type":"dev_t","value":12},{"name":"inode","type":"unsigned long","value":174033},{"name":"count","type":"size_t","value":131072},{"name":"pos","type":"off_t","value":0}]}
    ```

   !!! Note
       You can read captured files read at `/tmp/tracee/out`:
       ```console
       sudo cat /tmp/tracee/out/host/read.dev-12.inode-176203
       ```

        ```text
        read testing 123
        ```

1. **Executed Files**

    Anytime a **binary is executed**, the binary file will be captured. If the
    same binary is executed multiple times, it will be captured just once.

    ```console
    sudo ./dist/tracee \
       --output json \
       --scope comm=bash \
       --scope follow \
       --output option:parse-arguments \
       --capture dir:/tmp/tracee/ \
       --capture exec
    ```

    ```console
    /bin/ls
    ```

    ```json
    {"timestamp":1657322300531713371,"threadStartTime":620311624458929,"processorId":21,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"56","eventName":"clone","argsNum":5,"returnValue":3331757,"stackAddresses":null,"syscall":"clone","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"flags","type":"string","value":"CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID"},{"name":"stack","type":"void*","value":"0x0"},{"name":"parent_tid","type":"int*","value":"0x0"},{"name":"child_tid","type":"int*","value":"0x7fd7ce0d3a10"},{"name":"tls","type":"unsigned long","value":0}]}
    {"timestamp":1657322300534562489,"threadStartTime":620311624458929,"processorId":21,"processId":2578238,"cgroupId":1,"threadId":2578238,"parentProcessId":2578237,"hostProcessId":2578238,"hostThreadId":2578238,"hostParentProcessId":2578237,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"3","eventName":"close","argsNum":1,"returnValue":0,"stackAddresses":null,"syscall":"close","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"fd","type":"int","value":3}]}
    ```

    !!! Note
        You will have a copy of each executed file written at `/tmp/tracee/out`:
        ```console
        ldd /bin/ls
        ```

        ```text
        linux-vdso.so.1 (0x00007ffca632c000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f9a930d5000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a92ead000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007f9a92e16000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9a93136000)
        ```

        ```console
        ldd /tmp/tracee/out/host/exec.1657322052835478987.ls
        ```

        ```text
        linux-vdso.so.1 (0x00007ffe337fb000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007feeb1fa5000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007feeb1d7d000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007feeb1ce6000)
        /lib64/ld-linux-x86-64.so.2 (0x00007feeb2006000)

        ```console
        sudo chmod +x /tmp/tracee/out/host/exec.1657322052835478987.ls
        /tmp/tracee/out/host/exec.1657322052835478987.ls
        ```

1. **Memory Files**

    Anytime a **memory unpacker** is detected, the suspicious **memory region**
    will be captured. This is triggered when memory protection changes from
    **Write+Execute** to **Write**.

    ```console
    sudo ./dist/tracee \
       --output none \
       --scope comm=bash \
       --scope follow \
       --capture dir:/tmp/tracee/ \
       --capture mem
    ```

    !!! Note
        You may opt not to have any output from **tracee** with `--output none`
        command flag is given. This makes tracee to work in capture mode only.

1. **Network PCAP Files**

    Anytime a **network packet** is delivered to a process, traced by tracee,
    this packet might be captured into one or multiple pcap files.

    !!! Attention
        The default behavior when capturing network traffic is to capture
        ALL traffic, despite given event filters. If you want to make
        capture feature to follow the given event filters, like for example
        capturing DNS events only, then you have to provide `--capture
        pcap-options:filtered` argument in the command line. Then only
        net_packet_XXX events will be captured (IPv4, IPv6, TCP, UDP,
        ICMP, ICMPv6, DNS, HTTP, etc).

    A good way to test this behavior is to execute:

    ```console
    sudo ./dist/tracee \
        --events net_packet_ipv4 \
        --capture network \
        --capture pcap-options:filtered
    ```

    and observe a single **pcap file** for all ipv4 packets created:

    ```console
    find /tmp/tracee/out/pcap/
    ```

    ```text
    /tmp/tracee/out/pcap/
    /tmp/tracee/out/pcap/single.pcap
    ```

    You can select only dns packets, for example:

    ```console
    sudo ./dist/tracee \
        --events net_packet_dns \
        --capture network \
        --capture pcap-options:filtered
    ```

    and the file `/tmp/tracee/out/pcap/single.pcap` would only contain DNS
    related packets:

    ```console
    find /tmp/tracee/out/pcap/
    ```

    ```text
    /tmp/tracee/out/pcap/
    /tmp/tracee/out/pcap/single.pcap
    ```

    ```console
    sudo tcpdump -n -r /tmp/tracee/out/pcap/single.pcap | head -2
    ```

    ```text
    reading from file /tmp/tracee/out/pcap/single.pcap, link-type NULL (BSD loopback), snapshot length 262144
    16:53:48.870629 IP 127.0.0.1.55569 > 127.0.0.53.53: 33361+ [1au] A? www.uol.com.br. (43)
    16:53:48.870690 IP 127.0.0.1.55569 > 127.0.0.53.53: 25943+ [1au] AAAA? www.uol.com.br. (43)
    ```

    A great thing is that you may have multiple pcap files, divided by:

    1. single: a single pcap file containing all packets (the default)
    1. process: one file per process executed, ordered by host and container
    1. container: one file for the host and one pcap file per container
    1. per-command: one file per command executed (even if multiple times)

    and you can even have multiple ways at the same time. Example: a ping
    command is executed inside a container. You want to summarize captured
    traffic per container and per command. You will find the same captured
    data for that ping command inside `commands/container_id/ping.pcap` and
    inside `containers/container_id.pcap`.

    ```console
    sudo ./dist/tracee \
        --events net_packet_icmp \
        --capture network \
        --capture pcap-options:filtered \
        --capture pcap:process,container,command
    ```

    ```console
    cd /tmp/tracee/out
    find pcap
    ```

    ```text
    pcap
    pcap/commands
    pcap/commands/b86533d11f3
    pcap/commands/b86533d11f3/ping.pcap
    pcap/commands/host
    pcap/commands/host/sshd.pcap
    pcap/commands/host/zerotier-one.pcap
    pcap/commands/host/node.pcap
    pcap/commands/fd95a035ce5
    pcap/commands/fd95a035ce5/ping.pcap
    pcap/processes
    pcap/processes/b86533d11f3
    pcap/processes/b86533d11f3/ping_1261180_1663772450241192.pcap
    pcap/processes/host
    pcap/processes/host/node_186708_1573567360495399.pcap
    pcap/processes/host/node_1196826_1662656211119567.pcap
    pcap/processes/host/zerotier-one_7882_137007714376.pcap
    pcap/processes/host/sshd_1196773_1662654999660718.pcap
    pcap/processes/fd95a035ce5
    pcap/processes/fd95a035ce5/ping_1261163_1663769383806467.pcap
    pcap/containers
    pcap/containers/host.pcap
    pcap/containers/b86533d11f3.pcap
    pcap/containers/fd95a035ce5.pcap
    ```

    you can see the packets by executing tcpdump on any pcap file:

    ```console
    tcpdump -r pcap/containers/b86533d11f3.pcap
    ```

    ```text
    reading from file pcap/containers/b86533d11f3.pcap, link-type NULL (BSD loopback), snapshot length 65535
    02:52:00.524035 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 476, length 64
    02:52:00.533145 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 476, length 64
    02:52:01.525455 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 477, length 64
    02:52:01.535414 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 477, length 64
    02:52:02.526715 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 478, length 64
    02:52:02.536444 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 478, length 64
    02:52:03.528739 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 479, length 64
    02:52:03.538622 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 479, length 64
    ```

    ```console
    tcpdump -r pcap/commands/b86533d11f3/ping.pcap
    ```

    ```text
    reading from file pcap/commands/b86533d11f3/ping.pcap, link-type NULL (BSD loopback), snapshot length 65535
    02:52:00.524035 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 476, length 64
    02:52:00.533145 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 476, length 64
    02:52:01.525455 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 477, length 64
    02:52:01.535414 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 477, length 64
    02:52:02.526715 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 478, length 64
    02:52:02.536444 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 478, length 64
    02:52:03.528739 IP 172.17.0.3 > dns.google: ICMP echo request, id 5, seq 479, length 64
    02:52:03.538622 IP dns.google > 172.17.0.3: ICMP echo reply, id 5, seq 479, length 64
    ```

    !!! Note
        Note that the same packets were written to 2 different pcap files: the
        pcap file describing the container `b86533d11f3` (because it was
        executing a single process: ping) and the pcap file describing ANY ping
        command executed in that container (commands/b86533d11f3/ping.pcap).

    The format for the pcap filenames inside `output_dir` is the following:

    1. **single**:  
       ./pcap/single.pcap
    1. **processes**:  
       ./pcap/processes/`container_id`/`process_comm`/`host_tid`/`task_starttime`.pcap
    1. **containers**:  
       ./pcap/containers/`container_id`.pcap
    1. **commands**:  
       ./pcap/commands/`container_id`/`process_comm`.pcap

    !!! Attention
        By default, all pcap files will contain packets with headers only. That
        might too little for introspection, since sometimes one might be
        interested in a few bytes of the captured packet (or event it all). Next
        item shows how to capture a specific packet payload size.

    In order to capture a specific payload size you may specify:

    ```console
    sudo ./dist/tracee \
        --events net_packet_tcp \
        --capture network \
        --capture pcap-options:filtered \
        --capture pcap:single,command \
        --capture pcap-snaplen:default
    ```

    To capture packet headers + 96 bytes of payload. Or replace `default` by:

    1. headers: capture up to L4 headers only
    1. max: full sized packets into pcap. WARNING: big pcap files.
    1. **256b**, **512b**, **1024b**, ... (any number plus "b")
    1. **16kb**, **32kb**, **64kb**,  ... (any number plus "kb")

    > when specifying a payload size, it refers to the payload AFTER the layer4
    > headers (and not the entire packet length).

1. **Loaded Kernel Modules**

    Anytime a **kernel module** is loaded, the binary file will be captured.
    If the same binary is loaded multiple times, it will be captured just once.

    ```console
    sudo ./dist/tracee \
        --output none \
        --scope comm=bash \
        --scope follow \
        --capture clear-dir \
        --capture module
    ```

    Captured module will be found in tracee destination directory, just like
    any other captured file would be:

    ```console
    sudo ls /tmp/tracee/out/host
    ```

    ```text
    module.dev-271581185.inode-4071826.pid-3668786.c8b62228208f4bdbf21df09c01046b73dd44733841675bf3c0ff969fbedab616
    ```

    AND, the captured module is an exact copy of the loaded module:

    ```console
    sudo rmmod lkm_example
    sudo insmod /tmp/tracee/out/host/module.dev-271581185.inode-4071826.pid-3668786.c8b62228208f4bdbf21df09c01046b73dd44733841675bf3c0ff969fbedab616
    ```

    ```console
    lsmod | grep example

    ```text
    lkm_example            16384  0
    ```

    ```console
    sudo rmmod lkm_example
    ```

    you can even load/unload it.

    !!! Note
        Example kernel module taken from [this blog]

[this blog]: https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234

1. **BPF programs**

    Wheneber a **BPF program** is loaded, the BPF bytecode will be captured.
    This captured bytecode represents the BPF program as it was loaded by the loading process.
    It is basically the BPF section of the compiled ELF that loads the BPF program, which contains the program instructions themselves.
    You can disassemble the bytecode with the help of `binutils-bpf` package and the following command line:
    `objdump -D -b binary -m bpf <path>`

     ```text
     $ sudo ./dist/tracee-ebpf \
        --output none \
        --scope comm=bash \
        --scope follow \
        --capture clear-dir \
        --capture bpf
     ```

    Captured bpf bytecode will be found in tracee destination directory, just like
    any other captured file would be:

     ```text
     $ sudo ls /tmp/tracee/out/host
       bpf.name-test_prog.pid-3668786.c8b62228208f4bdbf21df09c01046b73dd44733841675bf3c0ff969fbedab616
     ```
   The hex value after the last "." is the hash of the bpf bytecode.
