# Output Options

Tracee supports different output options for customizing the way events are printed. For a complete list of available options.

Available options:

1. **option:stack-addresses**  

    Makes it possible to pick stack memory address from each event.

    ```
    output:
        options:
            stack-addresses: true
    ```

2. **option:parse-arguments**

    In order to have a better experience with the output provided by
    **tracee**, you may opt to parse event arguments to a **human
    *readable** format.

    ```
    output:
        options:
            parse-arguments: true
    ```

3. **option:exec-env**

    Sometimes it is also important to know the execution environment variables
    whenever an event is detected, specially when detecting **execve** event.

    ```
    output:
        options:
            exec-env: true

    ```

4. **option:exec-hash**

    This is a special output option for **sched_process_exec** so user can get
    the **file hash** and **process ctime** (particularly interesting if you
    would like to compare executed binaries from a list of known hashes, for
    example).

    ```
    output:
        options:
            exec-hash: true
    ```
5. **option:relative-time**

    The `relative-time` output option filters all the events since the boot time of the system.

    ```
    output:
        options:
            relative-time: true
    ```

6. **option:sort-events**

    This makes it possible to sort the events as they happened. Especially in systems where Tracee tracks lots of events, it can happen that they are received unordered. More information is provided in the [deep-dive](../deep-dive/ordering-events.md) section of the documentation.

    ```
    output:
        options:
                sort-events: false
    ```
