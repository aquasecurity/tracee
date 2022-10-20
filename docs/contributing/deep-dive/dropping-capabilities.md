# Special: Dropping Capabilities

**tracee-ebpf** and **tracee-rules** both try to reduce capabilities upon
startup.

## Dropping Errors

!!! Attention
    This session is important if you're facing errors while **tracee-ebpf** is
    trying to drop its capabilities or any other permissions errors.

Some environments **won't allow capabilities dropping** because of permission
issues (for example - **AWS Lambdas**).

> It might be a result of seccomp filter for example, restricting syscalls
> access.

Failure in capabilities dropping will result tracee's exit with a matching
error, to **guarantee that tracee isn't running with excess capabilities
without the user agreement**.

To **allow tracee to run with high capabilities** and prevent errors, the
`--allow-high-capabilities` flag can be used in tracee-rules, or
`--caps allow-failed-drop` in tracee-ebpf. For docker users, to allow
**tracee-ebpf** high capabilities the environment variable
`ALLOW_HIGH_CAPABILITIES=1` should be used.

## Missing Capabilities Errors

New features and refactoring might result missing capabilities for **tracee-ebpf**.
This may cause a wide variety of errors.

Our team tries to solve bugs as quickly as possible, but it might
still take some time to solve some bugs. Moreover, after a bug is fixed
it might take some time until a new version of Tracee is released.

To fix specific missing capabilities errors locally, users can add capabilities
using the `--caps add` flag to tracee-ebpf. For docker users, the environment variable
`CAPS_TO_PRESERVE=<list_of_capabilities>` should be used.

In addition, the `--caps cancel-drop` flag can be used to cancel capability
dropping of tracee-ebpf. For docker users, the environment variable
`CANCEL_CAPS_DROP=1` should be used. **We advise to not use this option unless required**.
