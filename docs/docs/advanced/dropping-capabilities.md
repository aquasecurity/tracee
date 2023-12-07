# Special: Environment Capabilities

## Introduction to Capabilities (quoting parts of kernel docs)

For the purpose of performing permission checks, traditional UNIX
implementations distinguish two categories of processes: privileged processes
(whose effective user ID is 0, referred to as superuser or root), and
unprivileged processes (whose effective UID is nonzero).

Privileged processes bypass all kernel permission checks, while unprivileged
processes are subject to full permission checking based on the process's
credentials (usually: effective UID, effective GID, and supplementary group
list).

Linux divides the privileges traditionally associated with superuser into
distinct units, known as capabilities, which can be independently enabled and
disabled. Capabilities are a per-thread attribute.

Thread capability sets:

* Permitted: This is a limiting superset for the effective capabilities that the
thread may assume. It is also a limiting superset for the capabilities that
may be added to the inheritable set by a thread that does not have the
CAP_SETPCAP capability in its effective set.

* Inheritable: This is a set of capabilities preserved across an execve(2).
Inheritable capabilities remain inheritable when executing any program, and
inheritable capabilities are added to the permitted set when executing a
program that has the corresponding bits set in the file inheritable
set.

* Effective: This is the set of capabilities used by the kernel to perform
permission checks for the thread.

* Bounding: The capability bounding set is a mechanism that can be used to limit
the capabilities that are gained during execve(2).

## Tracee and capabilities

**tracee** tries to reduce its capabilities during its execution. The way it
does is through different "execution protection rings":

* Full:     All capabilities are effective (less secure)
* EBPF:     eBPF needed capabilities + Base capabilities
* Specific: Specific capabilities (from time to time) + Base Capabilities
* Base:     None or Some capabilities always effective (more secure)

## Listing available capabilities

You may see all available capabilities in the running environment by running:

```console
capsh --print
```

## Bypass capabilities dropping feature

!!! Attention
    This session is important if you're facing errors related to **tracee**
    dropping its capabilities OR any other permission related errors.

Some environments **won't allow capabilities dropping** because of permission
issues (for example - **AWS Lambdas**).

> It might be a result of seccomp filter for example, restricting syscalls
> access.

Failure in capabilities dropping will result tracee's exit with a matching
error, to **guarantee that tracee isn't running with excess capabilities
without the user agreement**.

To **allow tracee to run with high capabilities**, and prevent those errors, the
`--capabilities bypass=true` flag can be used. For the docker container users,
the environment variable `CAPABILITIES_BYPASS=0|1` will have the same effect.

!!! Note
    Bypassing the capabilities drop will run **tracee** with all capabilities
    set as Effective and it is only recommended if you know what you are doing.

## Capabilities Errors (Missing or Too Permissive)

During development, tracee might have bugs related to capabilities dropping
feature: one event might not have its needed capabilities set as a dependency,
for example, and you might still want to use that event.

One way to have fine grained control of "execution time" effective capabilities
is to rely on following 2 command line flags:

- `--capabilities add=cap_X,cap_Y` (docker env variable CAPABILITIES_ADD)
- `--capabilities drop=cap_Y,capZ` (docker env variable CAPABILITIES_DROP)

The first will add given capabilities to the Base ring, the ring that describe
capabilities that will always be effective while tracee is running, so events
might be able to work. The last will remove the capabilities from that same
ring.
