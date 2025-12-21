---
title: TRACEE-STORES
section: 1
header: Tracee Stores Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-stores** - Configure data stores for DNS cache and process tree

## SYNOPSIS

tracee **\-\-stores** [dns|dns.max-entries=*size*|process|process.max-processes=*size*|process.max-threads=*size*|process.source=*source*|process.use-procfs] [**\-\-stores** ...]

## DESCRIPTION

The **\-\-stores** flag allows you to configure data stores for DNS cache and process tree functionality.

### DNS Store Options

- **dns**: Enable the DNS cache store with default settings. When enabled, Tracee will cache DNS query information for enrichment of network events.

- **dns.max-entries**=*size*: Enable the DNS cache store and set the maximum number of DNS query trees to cache. Default is 5000. Further queries may be cached regardless once the limit is reached. **Note**: Using this option automatically enables DNS, so you don't need to also specify `--stores dns`.

### Process Store Options

- **process**: Enable the process tree store with default settings. When enabled, Tracee will maintain a tree of processes and threads for enrichment of events.

- **process.max-processes**=*size*: Enable the process tree store and set the maximum number of processes to cache in the process tree. Default is 10928. This is an LRU cache that will evict least recently accessed entries when full. **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`.

- **process.max-threads**=*size*: Enable the process tree store and set the maximum number of threads to cache in the process tree. Default is 21856. This is an LRU cache that will evict least recently accessed entries when full. **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`.

- **process.source**=*source*: Enable the process tree store and set the source for process tree enrichment. Valid values are:
  - **signals**: Process tree is built from signals (default).
  - **events**: Process tree is built from events.
  - **both**: Process tree is built from both events and signals.
  
  **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`. If no source is specified, the default is `signals`.

- **process.use-procfs**: Enable the process tree store and enable procfs initialization and querying. When enabled, Tracee will:
  - Scan procfs during initialization to fill all existing processes and threads.
  - Query specific processes at runtime in case of missing information caused by missing events.

  **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`. The procfs query might increase the feature toll on CPU and memory. The runtime query might have a snowball effect on lost events, as it will reduce the system resources in the processes of filling missing information.

## EXAMPLES

1. Enable DNS cache:
   ```console
   --stores dns
   ```

2. Enable DNS cache with custom size:
   ```console
   --stores dns.max-entries=10000
   ```
   
   Note: `dns.max-entries` automatically enables DNS, so `--stores dns` is not needed.

3. Enable process tree:
   ```console
   --stores process
   ```

4. Enable process tree with custom cache sizes:
   ```console
   --stores process.max-processes=8192 --stores process.max-threads=16384
   ```
   
   Note: `process.max-processes` and `process.max-threads` automatically enable process, so `--stores process` is not needed.

5. Enable process tree with events source:
   ```console
   --stores process.source=events
   ```
   
   Note: `process.source` automatically enables process, so `--stores process` is not needed.

6. Enable process tree with both events and signals sources:
   ```console
   --stores process.source=both
   ```
   
   Note: `process.source` automatically enables process, so `--stores process` is not needed.

7. Enable process tree with procfs support:
   ```console
   --stores process.use-procfs
   ```
   
   Note: `process.use-procfs` automatically enables process, so `--stores process` is not needed.

8. Combine DNS and process stores:
   ```console
   --stores dns.max-entries=5000 --stores process.source=both --stores process.max-processes=8192
   ```
   
   Note: Since `dns.max-entries` and `process.source` automatically enable their respective stores, you don't need `--stores dns` or `--stores process`.

9. Complete configuration example:
   ```console
   --stores dns.max-entries=5000 --stores process.max-processes=8192 --stores process.max-threads=16384 --stores process.source=both --stores process.use-procfs
   ```
   
   Note: All process options automatically enable process, and `dns.max-entries` automatically enables DNS, so you don't need `--stores dns` or `--stores process`.

Please refer to the [DataStore API documentation](../detectors/datastore-api.md) for information about using these stores in detectors:
- [DNSStore](../detectors/datastore-api.md#dnsstore) - DNS cache access
- [ProcessStore](../detectors/datastore-api.md#processstore) - Process tree and ancestry

