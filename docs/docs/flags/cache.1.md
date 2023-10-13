---
title: TRACEE-CACHE
section: 1
header: Tracee Cache Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-cache** - Select different cache types for the event pipeline queueing

## SYNOPSIS

tracee **\-\-cache** [none|cache-type=<type\>] [**\-\-cache** mem-cache-size=<size\>]

## DESCRIPTION

The **\-\-cache** flag allows you to select different cache types for the event pipeline queueing.

Possible options for **cache-type** are:

- **none**: No event caching in the pipeline (default) - similar to **\-\-cache none**.
- **mem**: Enables caching events in memory.

If **cache-type=mem** is chosen, you can also set the memory cache size in megabytes (MB) using the **mem-cache-size** option. This option only works when **cache-type=mem**.

## EXAMPLES

- To cache events in memory using the default values, use the following flag:

  ```console
  --cache cache-type=mem
  ```

- To cache events in memory and set the memory cache size to 1024 MB, use the following flag:

  ```console
  --cache cache-type=mem --cache mem-cache-size=1024
  ```

- To disable event caching in the pipeline, use the following flag:

  ```console
  --cache none
  ```
