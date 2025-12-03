---
title: TRACEE-ARTIFACTS
section: 1
header: Tracee Artifacts Flag Manual
date: 2024/06
...

## NAME

tracee **\-\-artifacts** - Capture artifacts that were written, executed, or found to be suspicious

## SYNOPSIS

tracee **\-\-artifacts** <artifact-option[=value]\> ...

## DESCRIPTION

The **\-\-artifacts** flag allows you to capture artifacts that were written, executed, or found to be suspicious during the execution of Tracee. The captured artifacts will appear in the 'output-path' directory.

Possible artifacts options:

- **file-write.enabled**: Capture written files.
- **file-write.filters=\<filter\>**: Filter for file writes (multiple allowed). Format: \<filter_type\>=\<filter_value\>
- **file-read.enabled**: Capture read files.
- **file-read.filters=\<filter\>**: Filter for file reads (multiple allowed). Format: \<filter_type\>=\<filter_value\>
- **executable.enabled**: Capture executed files.
- **kernel-modules.enabled**: Capture loaded kernel modules.
- **bpf-programs.enabled**: Capture loaded BPF programs bytecode.
- **memory-regions.enabled**: Capture memory regions that had write+execute (w+x) protection and then changed to execute (x) only.
- **network.enabled**: Capture network traffic. Only TCP/UDP/ICMP protocols are currently supported.
- **network.pcap.split=\<split_mode\>**: Capture separate pcap files organized by split mode: single, process, container, command (comma-separated).
- **network.pcap.options=\<option\>**: Network capturing options: none (default) or filtered.
- **network.pcap.snaplen=\<size\>**: Sets captured payload from each packet: default, headers, max, or SIZE (e.g., 256b, 512b, 1kb, 2kb, 4kb).
- **dir.path=\<path\>**: Path where tracee will save produced artifacts. The artifact will be saved into an 'out' subdirectory (default: /tmp/tracee).
- **dir.clear**: Clear the captured artifacts output dir before starting (default: false).

### File Capture Filters

Files captured upon read/write can be filtered to catch only specific IO operations. The different filter types have a logical 'AND' between them but a logical 'OR' between filters of the same type. The filter format is as follows: \<filter_type\>=\<filter_value\>

Filter types:

- **path**: A filter for the file path prefix (up to 50 characters). Up to 3 filters can be given. Format: path=/path/prefix\*
- **type**: A file type from the following options: 'regular', 'pipe', 'socket' and 'elf'. Format: type=regular
- **fd**: The file descriptor of the file. Can be one of the three standards: 'stdin', 'stdout' and 'stderr'. Format: fd=stdout

### Network Capture Notes

- Pcap Files:
  - If you only specify **\-\-artifacts network.enabled**, you will have a single file with all network traffic.
  - You can use **network.pcap.split=xxx,yyy** to have more than one pcap file, split by different means.

- Pcap Options:
  - If you do not specify **network.pcap.options** (or set to none), you will capture ALL network traffic into your pcap files.
  - If you specify **network.pcap.options=filtered**, events being traced will define what network traffic will be captured.

- Snap Length:
  - If you do not specify a snaplen, the default is headers only (incomplete packets in tcpdump).
  - If you specify **max** as snaplen, you will get full packets contents (pcap files will be large).
  - If you specify **headers** as snaplen, you will only get L2/L3 headers in captured packets.
  - If you specify **headers** but trace for **net_packet_dns** events, L4 DNS header will be captured.
  - If you specify **headers** but trace for **net_packet_http** events, only L2/L3 headers will be captured.

## EXAMPLES

### File capture

- To capture executed files into the default output directory, use the following flag:

  ```console
  --artifacts executable.enabled
  ```

- To capture executed files into a specific directory, clear the directory before starting, use the following flags:

  ```console
  --artifacts executable.enabled --artifacts dir.path=/my/dir --artifacts dir.clear
  ```

- To capture files that were written into anywhere under /usr/bin/ or /etc/, use the following flags:

  ```console
  --artifacts file-write.enabled --artifacts file-write.filters=path=/usr/bin/* --artifacts file-write.filters=path=/etc/*
  ```

- To capture file writes to socket files that are the 'stdout' of the writing process, use the following flags:

  ```console
  --artifacts file-write.enabled --artifacts file-write.filters=type=socket --artifacts file-write.filters=fd=stdout
  ```

### Network Capture

- To capture network traffic, use the following flag:

  ```console
  --artifacts network.enabled
  ```

- To capture network traffic and save separate pcap files for processes and commands, use the following flags:

  ```console
  --artifacts network.enabled --artifacts network.pcap.split=process,command
  ```

- To capture network traffic and save pcap files containing only traced/filtered packets, use the following flags:

  ```console
  --artifacts network.enabled --artifacts network.pcap.options=filtered
  ```

- To capture network traffic and set the captured payload from each packet to 1KB, use the following flags:

  ```console
  --artifacts network.enabled --artifacts network.pcap.snaplen=1kb
  ```

- To capture network traffic and save pcap files for containers and commands, use the following flags:

  ```console
  --artifacts network.enabled --artifacts network.pcap.split=container,command
  ```

