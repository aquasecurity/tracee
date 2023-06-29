# Rego Signatures

!!! Tip
    Differently than [golang built-in signatures](./golang.md), with Rego
    signatures you are able to add and/or remove signatures to Tracee without
    the need of recompiling it (or re-distributing the binary) BUT it may come
    with a performance price to pay.

In order to create your own [Rego] signature you need to create a `.rego`
file that has the following Rego Rules (now, in this context, rules are Rego's
language constructs):

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
        "eventName": "mine",
        "description": "My Own Signature Detects Stuff",
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

After placing your `signature_example.rego` inside `signatures/rego` directory you
may execute **tracee** selecting only the event you just created, if that is
what you want:

```console
sudo ./dist/tracee \
    --output json
    --signatures-dir signatures/rego \
    --events mine
```

```json
{"timestamp":1680190419485136510,"threadStartTime":1680190419369780383,"processorId":4,"processId":320908,"cgroupId":16273,"threadId":320908,"parentProcessId":1635,"hostProcessId":320908,"hostThreadId":320908,"hostParentProcessId":1635,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"terminator","hostName":"hb","container":{},"kubernetes":{},"eventId":"6000","eventName":"mine","matchedPolicies":[""],"argsNum":0,"returnValue":10,"syscall":"","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[],"metadata":{"Version":"0.1.0","Description":"My Own Signature Detects Stuff","Tags":null,"Properties":{"signatureID":"Mine-0.1.0","signatureName":"My Own Signature"}}}
```

See [signatures/rego] for example Rego signatures.

[Rego]: https://www.openpolicyagent.org/docs/latest/#rego
[signatures/rego]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/signatures/rego
