---
title: TRACEE-STORES
section: 1
header: Tracee Stores Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-stores** - Configure data stores for DNS cache and process tree

## SYNOPSIS

tracee **\-\-stores** [dns|dns.max-entries=*size*|process|process.max-processes=*size*|process.max-threads=*size*] [**\-\-stores** ...]

## DESCRIPTION

The **\-\-stores** flag allows you to configure data stores for DNS cache and process tree functionality.

### DNS Store Options

- **dns**: Enable the DNS cache store with default settings. When enabled, Tracee will cache DNS query information for enrichment of network events.

- **dns.max-entries**=*size*: Enable the DNS cache store and set the maximum number of DNS query trees to cache. Default is 5000. Further queries may be cached regardless once the limit is reached. **Note**: Using this option automatically enables DNS, so you don't need to also specify `--stores dns`.

### Process Store Options

- **process**: Enable the process tree store with default settings. When enabled, Tracee will maintain a tree of processes and threads for enrichment of events. **Note: Process tree is enabled by default.**

- **process.max-processes**=*size*: Enable the process tree store and set the maximum number of processes to cache in the process tree. Default is 10000. This is an LRU cache that will evict least recently accessed entries when full. **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`.

- **process.max-threads**=*size*: Enable the process tree store and set the maximum number of threads to cache in the process tree. Default is 0 (thread tracking disabled to save memory). This is an LRU cache that will evict least recently accessed entries when full. **Note**: Using this option automatically enables process, so you don't need to also specify `--stores process`.

**Note**: Procfs initialization happens automatically when the process tree is enabled. At startup, Tracee scans `/proc` to populate the process tree with all existing processes and threads, ensuring complete process ancestry information is available.

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

5. Combine DNS and process stores:
   ```console
   --stores dns.max-entries=5000 --stores process.max-processes=8192
   ```
   
   Note: Since `dns.max-entries` automatically enables DNS and `process.max-processes` automatically enables process, you don't need `--stores dns` or `--stores process`.

6. Complete configuration example:
   ```console
   --stores dns.max-entries=5000 --stores process.max-processes=8192 --stores process.max-threads=16384
   ```
   
   Note: All process options automatically enable process, and `dns.max-entries` automatically enables DNS, so you don't need `--stores dns` or `--stores process`.

Please refer to the [DataStore API documentation](../detectors/datastore-api.md) for information about using these stores in detectors:

- [DNSStore](../detectors/datastore-api.md#dnsstore) - DNS cache access
- [ProcessStore](../detectors/datastore-api.md#processstore) - Process tree and ancestry

