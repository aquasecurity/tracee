# Rego Signatures

!!! Tip
    Differently than [golang built-in signatures](./golang.md), with Rego
    signatures you are able to add and/or remove signatures to Tracee without
    the need of recompiling it (or re-distributing the binary) BUT it may come
    with a performance price to pay.

In order to create your own [Rego] signature you need to create a `.rego`
file in the **rules directory** that has the following Rego Rules (now, in
this context, rules are Rego's language constructs):

!!! __rego_metadoc__ Note
    A *document* rule that defines the rule's metadata.

!!! tracee_selected_events Tip
    A *set* rule that defines the event selectors.

!!! tracee_match Attention
    A *boolean* or a *document* rule that defines the logic of the signature.
    If bool is "returned", a true evaluation will generate a Finding with no
    data. If a document is "returned", any non-empty evaluation will generate a
    Finding with the returned document as the Finding's "Data".

----

!!! Signature Example
    ```opa
    package tracee.Mine
    
    import data.tracee.helpers
    
    __rego_metadoc__ := {
        "id": "Mine-0.1.0",
        "version": "0.1.0",
        "name": "My Own Signature",
        "description": "My Own Signature Detects Stuff",
        "tags": ["linux"],
    }
    
    eventSelectors := [
        {
            "source": "tracee",
            "name": "openat",
        },
        {
            "source": "tracee",
            "name": "execve",
        },
    ]
    
    tracee_selected_events[eventSelector] {
    	eventSelector := eventSelectors[_]
    }
    
    tracee_match {
        input.eventName == "openat"
        arg_value = helpers.get_tracee_argument("pathname")
        startswith(arg_value, "/etc/passwd")
    }
    
    tracee_match {
        input.eventName == "execve"
        arg_value = helpers.get_tracee_argument("pathname")
        startswith(arg_value, "/etc/passwd")
    }
    ```

After placing your `signature_example.rego` inside `dist/signatures` directory you
may execute **tracee** selecting only the event you just created, if that is
what you want:

```text
$ sudo ./dist/tracee-ebpf \
    --output json \
    --filter comm=bash \
    --filter follow \
    --output option:parse-arguments \
    -trace event=$(./dist/tracee-rules --rules Mine-0.1.0 --list-events) \
    | ./dist/tracee-rules \
    --input-tracee format:json \
    --input-tracee file:stdin \
    --rules Mine-0.1.0

Loaded 1 signature(s): [Mine-0.1.0]

*** Detection ***
Time: 2022-07-10T05:23:01Z
Signature ID: Mine-0.1.0
Signature: My Own Signature
Data: map[]
Command: batcat
Hostname: fujitsu
```

See [signatures/rego] for example Rego signatures.

[Rego]: https://www.openpolicyagent.org/docs/latest/#rego
[signatures/rego]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/signatures/rego
