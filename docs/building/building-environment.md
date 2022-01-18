# Creating a local building environment

## For the **impatient readers**:

### Build and execute `tracee-ebpf`:

```
$ make -f builder/Makefile.tracee-make alpine-prepare
$ make -f builder/Makefile.tracee-make alpine-shell

tracee@f64bb4a2f0b1[/tracee]$ make -f Makefile.one clean
tracee@f64bb4a2f0b1[/tracee]$ make -f Makefile.one tracee-ebpf
tracee@f64bb4a2f0b1[/tracee]$ sudo ./dist/tracee-ebpf \
	-o option:parse-arguments \
	--trace comm=bash \
	--trace follow \
	--trace event!='sched*'
```

Now, in your host's bash shell, execute a command. You will see all events (but
scheduler ones) being printed, in "table format", to stdout.

### Build and execute `tracee`:

```
$ make -f builder/Makefile.tracee-make alpine-prepare
$ make -f builder/Makefile.tracee-make alpine-shell

tracee@f64bb4a2f0b1[/tracee]$ make -f Makefile.one clean
tracee@f64bb4a2f0b1[/tracee]$ make -f Makefile.one all
tracee@f64bb4a2f0b1[/tracee]$ sudo ./dist/tracee-ebpf \
	-o format:json \
	-o option:parse-arguments \
	--trace comm=bash \
	--trace follow \
	--trace event!='sched*' | \
	./dist/tracee-rules \
	--input-tracee file:stdin \
	--input-tracee format:json
```

Now, in your host's bash shell, execute: `strace /bin/ls` and observe tracee
warning you about a possible risk (with its Anti-Debugging signature).

Now, for **more patient readers** ...

> Check [THIS](./containers.md) if you're looking for information about the
> containers images generation.

## How to use **Makefile.tracee-make**

In order to have a controlled building environment for tracee, tracee provides
a [Makefile.tracee-make](../builder/Makefile.tracee-make) file that allows you
to create and use docker controlled environments to build & test `tracee-ebpf`
and `tracee-rules`.

Two different environments are maintained for building tracee: **Alpine** and
**Ubuntu**.

The reason for that is that **Alpine Linux** is based in the
[musl](https://en.wikipedia.org/wiki/Musl) C standard library, while the
**Ubuntu Linux** uses [glibc](https://en.wikipedia.org/wiki/Glibc). By
supporting both building environments we can always be sure that the project
builds (and executes) correctly in both environments.

Be aware: local created containers, called `alpine-tracee-make` or
`ubuntu-tracee-make`, share the host source code directory. This means that, if
you build tracee binaries using `alpine` distribution, binaries `tracee-ebpf`
and `tracee-rules` might not be compatible to the Linux distribution from your
host OS.

> The best way to build a generic, and portable across different distributions,
> binary is to use STATIC=1 environment variable while executing "make":
>
> `$ STATIC=1 make -f Makefile.one tracee-ebpf`

### Creating a builder container

To create an **alpine-tracee-make** container:

```
$ make -f builder/Makefile.tracee-make alpine-prepare
```

To create an **ubuntu-tracee-make** container:

```
$ make -f builder/Makefile.tracee-make ubuntu-prepare
```

### Executing a builder shell

To execute an **alpine-tracee-make** shell:

```
$ make -f builder/Makefile.tracee-make alpine-shell
```

To execute an **ubuntu-tracee-make** shell:

```
$ make -f builder/Makefile.tracee-make ubuntu-shell
```

### Using `tracee-make` as the `make` replacement

Instead of executing a builder shell, one might use `alpine-tracee-make` or
`ubuntu-tracee-make` as a replacement for the `make` command:

```
$ make -f builder/Makefile.tracee-make ubuntu-prepare
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="help"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="clean"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="bpf-core"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="tracee-ebpf"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="all"
```

And run the commands directly in your host:

```
$ sudo ./dist/tracee-ebpf \
	-o option:parse-arguments \
	--trace comm=bash \
	--trace follow \
	--trace event!='sched*'
```

if the generated binary is compatible (depending on glibc version, for example).

If you don't want to depend on host's libraries versions, or if you are using
the `alpine-tracee-make` container as a replacement for `make`, and your host
is not an **Alpine Linux**, then you may set STATIC=1 variable so you can run
compiled binaries in your host:

```
$ make -f builder/Makefile.tracee-make alpine-prepare
$ make -f builder/Makefile.tracee-make alpine-make ARG="help"
$ STATIC=1 make -f builder/Makefile.tracee-make alpine-make ARG="all"
```

and execute the static binary from your host:

```
$ ldd dist/tracee-ebpf
	not a dynamic executable
```

> **Warning**: compiling `tracee-rules` with STATIC=1 won't allow you to use
> golang based signatures:
>
> ```
> 2021/12/13 13:27:21 error opening plugin /tracee/dist/rules/builtin.so:
> plugin.Open("/tracee/dist/rules/builtin.so"): Dynamic loading not supported
> ```
