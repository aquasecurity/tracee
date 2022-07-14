# Special: Dropping Capabilities

!!! Attention
    This session is important if you're facing errors while **tracee-ebpf** is
    trying to drop its capabilities.

**tracee-ebpf** and **tracee-rules** both try to reduce capabilities upon
startup.  

Some environments **won't allow capabilities dropping** because of permission
issues (for example - **AWS Lambdas**).

> It might be a result of seccomp filter for example, restricting syscalls
> access.

Failure in capabilities dropping will result tracee's exit with a matching
error, to **guarantee that tracee isn't running with excess capabilities
without the user agreement**.

To **allow tracee to run with high capabilities** and prevent errors, the
`--allow-high-capabilities` flag can be used. For docker users, to allow
**tracee-ebpf** high capabilities the environment variable
`ALLOW_HIGH_CAPABILITIES=1` should be used.
