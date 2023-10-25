# Custom Events

Tracee comes with lots of events, but you can extend it with events specific to your use case. There are two ways to extend Tracee with your own events:

1. [Go](./golang.md)
2. [Rego](./rego.md)

Once you created your own event, you can load it using the `signatures-dir` flag. For example, if you created your event in the path `/tmp/myevents` to use it you would start tracee with:

```
tracee --signatures-dir=/tmp/myevents
```

!!! Tip
    Tracee also uses the custom events to add a few events, if you pass your own directory
    for `signatures-dir` you will not load the tracee [signatures](../builtin/signatures/index.md),
    to avoid such problems, you can either place your own events under the same directory of the tracee custom events,
    or pass multiple directories for example:
    ```
    tracee --signatures-dir=/tmp/myevents --signatures-dir=./dist/signatures
    ```

👈 Please use the side-navigation on the left in order to browse the different topics.
