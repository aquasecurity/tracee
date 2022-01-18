# Creating a local building environment

> These instructions are meant to describe how to create a local building and
> execution environment. If you would like to build tracee container(s)
> image(s), [read this](./building-containers.md) instead.

## Quick steps (**impatient readers**)

* Build and execute `tracee-ebpf`:

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

Now, in your host's bash shell, execute a command. You will see all events
(except scheduler ones) being printed, in "table format", to stdout.

* Build and execute `tracee`:

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

## How to build and use the environment

In order to have a controlled building environment for tracee, tracee provides
a `Makefile.tracee-make` file that allows you to create and use docker
controlled environments to build & test `tracee-ebpf` and `tracee-rules`.

Two different environments are maintained for building tracee:

* Alpine
* Ubuntu

The reason for that is that **Alpine Linux** is based in the
[musl](https://en.wikipedia.org/wiki/Musl) C standard library, while the
**Ubuntu Linux** uses [glibc](https://en.wikipedia.org/wiki/Glibc). By
supporting both building environments we can always be sure that the project
builds (and executes) correctly in both environments.

Be aware: locally created containers, called `alpine-tracee-make` or
`ubuntu-tracee-make`, share the host source code directory. This means that, if
you build tracee binaries using `alpine` distribution, binaries `tracee-ebpf`
and `tracee-rules` might not be compatible to the Linux distribution from your
host OS.

### Creating a builder environment

To create an **alpine-tracee-make** container:

  ```
  $ make -f builder/Makefile.tracee-make alpine-prepare
  ```

To create an **ubuntu-tracee-make** container:

  ```
  $ make -f builder/Makefile.tracee-make ubuntu-prepare
  ```

### Executing a builder environment

To execute an **alpine-tracee-make** shell:

  ```
  $ make -f builder/Makefile.tracee-make alpine-shell
  ```

To execute an **ubuntu-tracee-make** shell:

  ```
  $ make -f builder/Makefile.tracee-make ubuntu-shell
  ```

### Using build environment as a **make** replacement

Instead of executing a builder shell, you may use `alpine-tracee-make`, or
`ubuntu-tracee-make`, as a replacement for the `make` command:

```
$ make -f builder/Makefile.tracee-make ubuntu-prepare
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="help"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="clean"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="bpf-core"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="tracee-ebpf"
$ make -f builder/Makefile.tracee-make ubuntu-make ARG="all"
```

And, after the compilation, run the commands directly in your host:

```
$ sudo ./dist/tracee-ebpf \
	-o option:parse-arguments \
	--trace comm=bash \
	--trace follow \
	--trace event!='sched*'
```

> **Note**: the generated binary must be compatible to your host (depending on
> glibc version, for example).

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
