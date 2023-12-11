# Output Options

Tracee supports different output options for customizing the way events are printed. For a complete list of available options.

Available options:

1. **stack-addresses**  

    Makes it possible to pick stack memory addresses from each event.

    ```
    output:
        options:
            stack-addresses: true
    ```

2. **parse-arguments**

    In order to have a better experience with the output provided by
    **tracee**, you may opt to parse event arguments to a **human
    *readable** format.

    ```
    output:
        options:
            parse-arguments: true
    ```

3. **exec-env**

    Sometimes it is also important to know the execution environment variables
    whenever an event is detected, specially when detecting **execve** event.

    ```
    output:
        options:
            exec-env: true

    ```

4. **exec-hash**

    This is a special output option for **sched_process_exec** so user can get
    the **file hash** and **process ctime** (particularly interesting if you
    would like to compare executed binaries from a list of known hashes, for
    example).

    ```
    output:
        options:
            exec-hash: dev-inode
    ```

5. **relative-time**

    The `relative-time` output option enables relative timestamp instead of wall timestamp for events.

    ```
    output:
        options:
            relative-time: true
    ```

6. **sort-events**

    This makes it possible to sort the events as they happened. Especially in systems where Tracee tracks lots of events, it can happen that they are received unordered. More information is provided in the [deep-dive](../deep-dive/ordering-events.md) section of the documentation.

    ```
    output:
        options:
                sort-events: true
    ```
