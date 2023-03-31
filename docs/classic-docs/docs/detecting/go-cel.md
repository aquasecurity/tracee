# Signatures written in Go-Cel (POC)

Tracee has introduced, on its last version, a new type of signatures, the
Common Expression Language, or [Go-Cel], signatures as a **PROOF OF CONCEPT**.

[Go-Cel]: https://github.com/google/cel-go

!!! Go-Cel Tip
    The Common Expression Language (CEL) is a non-Turing complete language
    designed for simplicity, speed, safety, and portability. CEL's C-like syntax
    looks nearly identical to equivalent expressions in C++, Go, Java, and
    TypeScript.

!!! Proof-of-Concept Attention
    Go-Cel based signatures are **experimental** and part an on going
    development **proof-of-concept**. The feature is not finished and writing
    signatures in Go-Cel might need tracee code updates such as creation of
    internal parser helpers and/or event types declaration in a protobuf
    wrapper internal structure.

This feature is enabled by placing CEL signature definition files (.cel, .yaml,
.yml) in the  the `--rules-dir` directory. Sample definition files can be found
in the `pkg/signatures/celsig/testdata/rules/` directory.

!!! Signature Example
    ```yaml
    kind: SignaturesConfig
    apiVersion: tracee.aquasecurity.github.io/v1alpha1
    signatures:
      - metadata:
          id: "Mine-0.1.0"
          version: "0.1.0"
          name: "My Own Signature"
          description: "My Own Signature Detects Stuff"
          tags:
            - "linux"
        eventSelectors:
          - source: tracee
            name: openat
        expression: |-
            input.eventName == 'openat' &&
            input.stringArg('pathname').startsWith('/etc/passwd')
    ```

After placing your `signature_example.yaml` inside `dist/signatures` directory you
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
    --input-tracee \
    format:json \
    --input-tracee file:stdin \
    --rules Mine-0.1.0

Loaded 1 signature(s): [Mine-0.1.0]

*** Detection ***
Time: 2022-07-10T05:49:48Z
Signature ID: Mine-0.1.0
Signature: My Own Signature
Data: map[]
Command: batcat
Hostname: fujitsu
```

!!! Experimental
    Like said previously, Go-Cel signatures are **experimental** and considered
    **proof-of-concept** for now. If you decide to develop Go-Cel signatures
    you may face some issues:

    1. Go-Cel depends on [protobuf] and `tracee.Event` is not yet a protobuf
       object. Because of that, there is a **wrapper** in place converting
       `tracee.Event` into `protobuf` so the evaluations can happen (check
       files inside `pkg/signatures/celsig/wrapper/` directory.

    2. When writing your signature, it might happen that the event you're
       filtering for does not have all of its arguments types wrapper into
       the protobuf wrapper. You may face errors such as:
       ```
       Unrecognized event arg: eventName: "openat" name: "mode" type: "mode_t" valueType: uint32 value: 0
       ```
       It means you have to add that type to Tracee's go-cel wrapper so it
       is able to evaluate it.

    3. Your signature might need helpers/macros that don't exist yet. A good
       source of an example is `pkg/signatures/celsig/library.go` file and
       functions:
        - `sockaddrArg`
        - `stringArg`
        - `argByName`

[protobuf]: https://github.com/golang/protobuf
