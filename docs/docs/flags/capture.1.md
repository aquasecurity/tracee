---
title: TRACEE-CAPTURE
section: 1
header: Tracee Capture Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-capture** - Capture artifacts that were written, executed, or found to be suspicious

## SYNOPSIS

tracee **\-\-capture** <[artifact:]capture-option[=value]\> ...

tracee **\-\-capture** <network\> [**\-\-capture** [pcap:option1(,option2...)|pcap-options:option|pcap-snaplen:size]] ...

## DESCRIPTION

The **\-\-capture** flag allows you to capture artifacts that were written, executed, or found to be suspicious during the execution of Tracee. The captured artifacts will appear in the 'output-path' directory.

Possible capture options:

- **[artifact:]write[=/path/prefix\*]**: Capture written files. You can provide a filter to only capture file writes whose path starts with a certain prefix (up to 50 characters). Up to 3 filters can be given.
- **[artifact:]read[=/path/prefix\*]**: Capture read files. You can provide a filter to only capture file reads whose path starts with a certain prefix (up to 50 characters). Up to 3 filters can be given.
- **[artifact:]exec**: Capture executed files.
- **[artifact:]module**: Capture loaded kernel modules.
- **[artifact:]bpf**: Capture loaded BPF programs bytecode.
- **[artifact:]mem**: Capture memory regions that had write+execute (w+x) protection and then changed to execute (x) only.
- **[artifact:]network**: Capture network traffic. Only TCP/UDP/ICMP protocols are currently supported.

### File Capture Filters

Files captured upon read/write can be filtered to catch only specific IO operations. The different filter types have a logical 'AND' between them but a logical 'OR' between filters of the same type. The filter format is as follows: <read/write\>:<filter-type\>=<filter-value\>

Filter types:

- **path**: A filter for the file path prefix (up to 50 characters). Up to 3 filters can be given. Identical to using '<read/write\>=/path/prefix\*'.
- **type**: A file type from the following options: 'regular', 'pipe', and 'socket'.
- **fd**: The file descriptor of the file. Can be one of the three standards: 'stdin', 'stdout', and 'stderr'.

### Network Capture Notes

- Pcap Files:
  - If you only specify **\-\-capture network**, you will have a single file with all network traffic.
  - You can use **pcap:xxx,yyy** to have more than one pcap file, split by different means.

- Pcap Options:
  - If you do not specify **pcap-options** (or set to none), you will capture ALL network traffic into your pcap files.
  - If you specify **pcap-options:filtered**, events being traced will define what network traffic will be captured.

- Snap Length:
  - If you do not specify a snaplen, the default is headers only (incomplete packets in tcpdump).
  - If you specify **max** as snaplen, you will get the full contents of each packet (pcap files will be large).
  - If you specify **headers** as snaplen, you will only get L2/L3 headers in captured packets.
  - If you specify **headers** but trace for **net_packet_dns** events, the L4 DNS header will be captured.
  - If you specify **headers** but trace for **net_packet_http** events, only L2/L3 headers will be captured.

## EXAMPLES

### File capture

- To capture executed files into the default output directory, use the following flag:

  ```console
  --capture exec
  ```

- To capture executed files into a specific directory, clear the directory before starting, use the following flags:

  ```console
  --capture exec --capture dir:/my/dir --capture clear-dir
  ```

- To capture files that were written into anywhere under /usr/bin/ or /etc/, use the following flags:

  ```console
  --capture write=/usr/bin/* --capture write=/etc/*
  ```

- To capture file writes to socket files that are the 'stdout' of the writing process, use the following flag:

  ```console
  --capture write:type=socket --capture write:fd=stdout
  ```

### Network Capture

- To capture network traffic, use the following flag:

  ```console
  --capture network
  ```

- To capture network traffic and save separate pcap files for processes and commands, use the following flag:

  ```console
  --capture network --capture pcap:process,command
  ```

- To capture network traffic and save pcap files containing only traced/filtered packets, use the following flag:

  ```console
  --capture network --capture pcap-options:filtered
  ```

- To capture network traffic and set the captured payload from each packet to 1KB, use the following flag:

  ```console
  --capture network --capture pcap-snaplen:1kb
  ```

- To capture network traffic and save pcap files for containers and commands, use the following flag:

  ```console
  --capture network --capture pcap:container,command
  ```
