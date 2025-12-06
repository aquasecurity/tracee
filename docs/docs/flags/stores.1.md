---
title: TRACEE-STORES
section: 1
header: Tracee Stores Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-stores** - Configure data stores for DNS cache and process tree

## SYNOPSIS

tracee **\-\-stores** [dns.enabled|dns.max-entries=*size*|process.enabled|process.max-processes=*size*|process.max-threads=*size*|process.source=*source*|process.use-procfs] [**\-\-stores** ...]

## DESCRIPTION

The **\-\-stores** flag allows you to configure data stores for DNS cache and process tree functionality.

### DNS Store Options

- **dns.enabled**: Enable the DNS cache store. When enabled, Tracee will cache DNS query information for enrichment of network events.

- **dns.max-entries**=*size*: Set the maximum number of DNS query trees to cache. Default is 5000. Further queries may be cached regardless once the limit is reached.

### Process Store Options

- **process.enabled**: Enable the process tree store. When enabled, Tracee will maintain a tree of processes and threads for enrichment of events.

- **process.max-processes**=*size*: Set the maximum number of processes to cache in the process tree. Default is 10928. This is an LRU cache that will evict least recently accessed entries when full.

- **process.max-threads**=*size*: Set the maximum number of threads to cache in the process tree. Default is 21856. This is an LRU cache that will evict least recently accessed entries when full.

- **process.source**=*source*: Set the source for process tree enrichment. Valid values are:
  - **none**: Process tree source is disabled (default).
  - **events**: Process tree is built from events.
  - **signals**: Process tree is built from signals.
  - **both**: Process tree is built from both events and signals.

- **process.use-procfs**: Enable procfs initialization and querying. When enabled, Tracee will:
  - Scan procfs during initialization to fill all existing processes and threads.
  - Query specific processes at runtime in case of missing information caused by missing events.

  Note: The procfs query might increase the feature toll on CPU and memory. The runtime query might have a snowball effect on lost events, as it will reduce the system resources in the processes of filling missing information.

## EXAMPLES

1. Enable DNS cache:
   ```console
   --stores dns.enabled
   ```

2. Enable DNS cache with custom size:
   ```console
   --stores dns.enabled --stores dns.max-entries=10000
   ```

3. Enable process tree:
   ```console
   --stores process.enabled
   ```

4. Enable process tree with custom cache sizes:
   ```console
   --stores process.enabled --stores process.max-processes=8192 --stores process.max-threads=16384
   ```

5. Enable process tree with events source:
   ```console
   --stores process.enabled --stores process.source=events
   ```

6. Enable process tree with both events and signals sources:
   ```console
   --stores process.enabled --stores process.source=both
   ```

7. Enable process tree with procfs support:
   ```console
   --stores process.enabled --stores process.use-procfs
   ```

8. Combine DNS and process stores:
   ```console
   --stores dns.enabled --stores dns.max-entries=5000 --stores process.enabled --stores process.source=both --stores process.max-processes=8192
   ```

9. Complete configuration example:
   ```console
   --stores dns.enabled --stores dns.max-entries=5000 --stores process.enabled --stores process.max-processes=8192 --stores process.max-threads=16384 --stores process.source=both --stores process.use-procfs
   ```

Please refer to the [DNS data source documentation](../advanced/data-sources/builtin/dns.md) and [Process Tree data source documentation](../advanced/data-sources/builtin/process-tree.md) for more information.

