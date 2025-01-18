# Process Tree Data

The `Process Tree` feature offers a structured view of processes and threads active in the system where Tracee is deployed. This setup facilitates quick access, updates, and tracking of processes, child processes, and related threads. All relationship and metadata data points for processes and threads are versioned, so you can pull data snapshots from a precise timestamp.

## Enabling the Feature

To switch on the `Process Tree` feature, run the command:

```bash
sudo tracee --output option:sort-events --output json --output option:parse-arguments --proctree source=both --events <event_type>
```

The underlying structure is populated using the core `sched_process_fork`, `sched_process_exec`, and `sched_process_exit` events and their data. There's also an option to bootstrap the process tree through a secondary route using internal signal events.

> Introducing this secondary event source is strategic: it reduces interference with actively traced events, leading to more accurate and granular updates in the process tree.

The number of processes retained in the tree hinges on cache size. We have two separate caches at play: one for processes and another for threads. The default cache size for processes is 16K, supporting tracking for up to 16,384 processes, while the thread cache is 32K, supporting tracking for up to 32,768 threads. On average, a configuration ratio of 2:1 (thread:cache) is defined, as one thread is created for every process. It's worth noting that these are LRU caches: once full, they'll evict the least recently accessed entries to accommodate fresh ones.

The process tree query the procfs upon initialization and during runtime to fill missing data:
* During initialization, it runs over all procfs to fill all existing processes and threads
* During runtime, it queries specific processes in the case of missing information caused by missing events. 

> [!CAUTION]
> The procfs query might increase the feature toll on CPU and memory. The runtime query might have a snowball effect on lost events, as it will reduce the system resources in the processes of filling missing information.

## Command Line Option

```bash
Example:
  --proctree source=[none|events|signals|both]
      none         | process tree is disabled (default).
      events       | process tree is built from events.
      signals      | process tree is built from signals.
      both         | process tree is built from both events and signals.
  --proctree process-cache=8192   | will cache up to 8192 processes in the tree (LRU cache).
  --proctree thread-cache=16384   | will cache up to 16384 threads in the tree (LRU cache).
  --proctree disable-procfs       | will disable procfs entirely.
  --proctree disable-procfs-query | will disable procfs quering during runtime.

Use comma OR use the flag multiple times to choose multiple options:
  --proctree source=A,process-cache=B,thread-cache=C
  --proctree process-cache=X --proctree thread-cache=Y
```

## Internal Data Organization

For those looking to develop signatures or simply understand the underpinnings of the `Process Tree` feature, a grasp on its internal data organization is invaluable. At its core, the system is structured for fast access, updating, and tracking.

### Hash Indexing

Every entity in the `Process Tree`, be it a process or thread, is indexed using a distinctive hash, formulated by combining a task's `start time` and `thread id`. Events in the system come attached with this hash in their context under the `EntityID` label.

### Core Components

1. **ProcessTree**: A macro view of all the processes and threads active in the system.
      - **Processes**: Defined either as a single-threaded application or the lead thread in a multi-thread application where the PID and TID are identical.
      - **Threads**: Also known as Light-Weight Processes by the kernel, they include both separate threads and the thread group leader. Threads under the same leader share a PID but possess distinct TIDs.

2. **Process**: A representation of individual processes. It contains:
      - The process metadata using the `TaskInfo` structure.
      - Information on its executable and interpreter using the `FileInfo` structure.
      - References to its parent, child processes, and sibling threads within the same thread group.

3. **Thread**: A representation of system threads. It contains:
      - The thread metadata using the `TaskInfo` structure.
      - Links to its parent and the its thread group leader.

4. **TaskInfo**: From task names, PIDs, TIDs, PPIDs, ownership details, to start and end timestamps, it's all cataloged here. As tasks evolve, certain properties might shift. These changes are recorded using changelogs.

5. **TaskInfo**: Acts as the central repository for task-specific attributes, including task names, PIDs (Process IDs), TIDs (Thread IDs), PPIDs (Parent Process IDs), and ownership UID/GID specifications. As task states transition within the kernel space, certain properties are subject to modification; such alterations are persistently tracked using changelogs.

6. **FileInfo**: This structure aggregates file metadata, capturing attributes like path, device, and inode details. In the realm of processes, `FileInfo` is responsible for maintaining records of binaries and interpreters, with alterations being tracked in changelogs.

## Process Tree Artifacts

In an upcoming update, the process tree will be enhanced with the addition of `artifacts`. Each process within the tree will be augmented with these "artifacts" to denote a task's various interactions and operations within the system. These artifacts, sourced from the tracing events provided by Tracee, offer a detailed depiction of a process's activities at the system level. Potential artifacts encompass:

- **File Operations**: Opened files, read/write activities, file deletion, and attribute changes.
- **Network Activities**: Sockets created, inbound/outbound connections, transmitted/received data packets, and protocol-specific operations (like TCP handshakes or UDP transmissions).
- **System Calls**: Executed syscalls, their arguments, and return values.
- **Memory Activities**: Memory allocation, deallocation, and page faults.
- **Device Interactions**: I/O operations on devices, device mounting/unmounting.
- **Kernel Module Activities**: Module load and unload operations.
- **Security-Related Activities**: Capabilities changes, SELinux operations, and AppArmor profile transitions.

This enhancement aims to offer developers and sysadmins a more detailed and granular view of task behaviors, paving the way for better system monitoring, diagnostics, and potential threat detection.

## Using the Process Tree

The process tree is only available internally, to tracee's components, but, through the [datasource](../overview.md) mechanism, signatures are able to query the tree data using the data source process tree API.

### Accessing the Process Tree Data Source

> Make sure to read [Golang Signatures](../../../events/custom/golang.md) first.

During the signature initialization, get the process tree data source instance:

```go
type e2eProcessTreeDataSource struct {
    cb            detect.SignatureHandler
    processTreeDS detect.DataSource
}

// Init is called once when the signature is loaded.
func (sig *e2eProcessTreeDataSource) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback

    processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
    if !ok {
        return fmt.Errorf("data source tracee/process_tree is not registered")
    }

    sig.processTreeDS = processTreeDataSource

    return nil
}
```

Then, to each event being handled, you will `Get()`, from the data source, the information needed. There are 3 types of information that can be requested:

1. datasource.ProcKey: for process information retrieval.
2. datasource.ThreadKey: for thread information retrieval.
3. datasource.LineageKey: for process lineage information retrieval.

Before explaining each request type and how to use them, consider the following signature `OnEvent()` handler example:

```go
// OnEvent is called when a subscribed event occurs.
func (sig *e2eProcessTreeDataSource) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("failed to cast event's payload")
    }

    switch eventObj.EventName {
    case "sched_process_exec":
        err = sig.check(&eventObj)
        if err != nil {
            return err
        }
    }

    // If all checks passed, send a finding
    m, _ := sig.GetMetadata()

    sig.cb(detect.Finding{
        SigMetadata: m,
        Event:       event,
        Data:        map[string]interface{}{},
    })

    return nil
}
```

Where the `check()` method will either be:

- checkProcess()
- checkThread()
- checkLineage()

> You can check related data structures directly in the [source code](https://github.com/aquasecurity/tracee/blob/7b095a8d9a11cbd11ac61d3eec4b0a0f77f66dd9/pkg/proctree/datasource.go#L59) for more information. Below you will find easy to understand examples.

### Processes Information Retrieval

Utilize the data source instance object saved from the `Init()` method, and use the information from the current event to query the process tree for details about the process that triggered the event.

```go
func (sig *e2eProcessTreeDataSource) checkProcess(eventObj *trace.Event) error {
    // Pick the process info from the data source
    procQueryAnswer, err := sig.processTreeDS.Get(
        datasource.ProcKey{
            EntityId: eventObj.ProcessEntityId,
            Time:     time.Unix(0, int64(eventObj.Timestamp)),
        })
    if err != nil {
        return fmt.Errorf(debug("could not find process"))
    }
    processInfo, ok := procQueryAnswer["process_info"].(datasource.ProcessInfo)
    if !ok {
        return fmt.Errorf(debug("could not extract info"))
    }

    // Compare PID, NS PID and PPID
    if processInfo.Pid != eventObj.HostProcessID {
        return fmt.Errorf(debug("no match for pid"))
    }
    if processInfo.NsPid != eventObj.ProcessID {
        return fmt.Errorf(debug("no match for ns pid"))
    }
    if processInfo.Ppid != eventObj.HostParentProcessID {
        return fmt.Errorf(debug("no match for ppid"))
    }

    // Check if the process lists itself in the list of its threads
    threadExist := false
    for tid := range processInfo.ThreadsIds {
        if tid == eventObj.HostThreadID {
            threadExist = true
            break
        }
    }
    if !threadExist {
        return fmt.Errorf(debug("process not listed as thread"))
    }
```

From the [data-sources documentation](../overview.md), you'll see that searches use keys. It's a bit like looking up information with a specific tag (or a key=value storage).

In the provided example, the `eventObj.ProcessEntityId` key (which is the process hash accompanying the event being handled) is utilized alongside the `datasource.ProcKey{}` argument to search for a process in the process tree. The resulting process is the one associated with the event under consideration.

> Keep in mind that users can specify a time to retrieve the information. By using the event timestamp, you obtain data available up to that specific moment.

Within the retrieved process object, you can find essential information about the running process. This includes details such as the binary associated with the executing program, the interpreter used for that program (either ld.so for ELF files or the relevant interpreters responsible for execution). In the near future, you can expect to see additional data related to the process, such as open files and sockets, known hosts and resolved names, utilized protocols, and more.

### Threads Information Retrieval

```go
// checkThread checks if thread info in the data source matches the info from the event.
func (sig *e2eProcessTreeDataSource) checkThread(eventObj *trace.Event) error {
    // Pick the thread info from the data source
    threadQueryAnswer, err := sig.processTreeDS.Get(
        datasource.ThreadKey{
            EntityId: eventObj.ThreadEntityId,
            Time:     time.Unix(0, int64(eventObj.Timestamp)),
        },
    )
    if err != nil {
        return fmt.Errorf(debug("could not find thread"))
    }
    threadInfo, ok := threadQueryAnswer["thread_info"].(datasource.ThreadInfo)
    if !ok {
        return fmt.Errorf(debug("could not extract info"))
    }

    // Compare TID, NS TID and PID
    if threadInfo.Tid != eventObj.HostThreadID {
        return fmt.Errorf(debug("no match for tid"))
    }
    if threadInfo.NsTid != eventObj.ThreadID {
        return fmt.Errorf(debug("no match for ns tid"))
    }
    if threadInfo.Pid != eventObj.HostProcessID {
        return fmt.Errorf(debug("no match for pid"))
    }

    return nil
}
```

In the example, the `eventObj.ThreadEntityId` key is used alongside the `datasource.ThreadKey{}` argument to search for a thread in the process tree. For applications that use only one thread, or the primary thread in multi-threaded applications, you'll find entries in both the processes and threads sections of the process tree. However, for simpler threads (commonly referred to as regular threads), they appear solely in the threads section.

### Lineage Information Retrieval

Using the `eventObj.ProcessEntityId` key (the process hash from the current event) in conjunction with the `datasource.LineageKey{}` argument allows retrieval of not just a singular process but multiple processes up the chain of ancestry: process, its parent, the parent's parent, and so forth. This capability is crucial for signatures that require analysis of process lineage and the associated artifacts of each process in that lineage.

```go
func (sig *e2eProcessTreeDataSource) checkLineage(eventObj *trace.Event) error {
    maxDepth := 5 // up to 5 ancestors + process itself

    // Pick the lineage info from the data source.
    lineageQueryAnswer, err := sig.processTreeDS.Get(
        datasource.LineageKey{
            EntityId: eventObj.ProcessEntityId,
            Time:     time.Unix(0, int64(eventObj.Timestamp)),
            MaxDepth: maxDepth,
        },
    )
    if err != nil {
        return fmt.Errorf(debug("could not find lineage"))
    }
    lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
    if !ok {
        return fmt.Errorf("failed to extract ProcessLineage from data")
    }

    compareMaps := func(map1, map2 map[int]uint32) bool {
        return true // (or false)
    }

    // First ancestor is the process itself: lineageInfo[0] (ProcessInfo object)

    for _, ancestor := range lineageInfo[1:] {
        // do something with "ancestor" ProcessInfo
    }

    return nil
}
```

