## Instructions on how to use **Makefile.docker**

In order to have a controlled building environment for tracee, tracee provides
a [Makefile.docker](./Makefile.docker) file that allows you to create and use
docker controlled environments to build & test `tracee-ebpf` and
`tracee-rules`.

### Creating a builder container

We're maintaining 2 different docker builder distros: **Alpine** and
**Ubuntu**. The reason for that is that Alpine is based in the
[musl](https://en.wikipedia.org/wiki/Musl) C standard library while Ubuntu uses
[glibc](https://en.wikipedia.org/wiki/Glibc). By doing that we can always be
sure that the project builds (and executes) correctly in both environments.

> The best way to build a generic, and portable across different distributions,
> binary is to use STATIC=1 environment variable while executing "make".

Both distributions also maintain, to each of their released versions, one
default toolchain and this is good for testing builds (as we can test multiple
toolchain versions,activelly supported/maintained, by having different
Dockerfile flavors only changing the distro version).

To create an **alpine-tracee-make** container:

```
$ make -f builder/Makefile.docker alpine-prepare
```

OR to create an **ubuntu-tracee-make** container:

```
$ make -f builder/Makefile.docker ubuntu-prepare
```

### Executing a builder shell

Execute an **alpine-tracee-make** shell:

```
$ make -f builder/Makefile.docker alpine-shell
```

OR execute an **ubuntu-tracee-make** shell:

```
$ make -f builder/Makefile.docker ubuntu-shell
```

### Executing compiled binaries inside builder shell

Execute **any** build commands inside picked builder shell:

```
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one clean
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one bpf-core
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one tracee-ebpf
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one tracee-rules
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one rules
tracee@402fbaa94e7f[/tracee]$ make -f Makefile.one bpf-nocore
...
```

Execute `tracee-ebpf`:

```
tracee@402fbaa94e7f[/tracee]$ sudo ./dist/tracee-ebpf --debug --trace 'event!=sched*'
```

and `tracee-rules` from inside builder shell:

```
tracee@402fbaa94e7f[/tracee]$ sudo ./dist/tracee-ebpf -o format:gob | \
    ./dist/tracee-rules --input-tracee file:stdin --input-tracee format:gob
```

> Do not mix the 2 **tracee-make** environments. If you compile `tracee-ebpf`,
> `tracee-rules`, or `rules` targets, inside **alpine** **tracee-make** env,
> then make sure to execute the given cmdlines in **alpine**. Same happens to
> the **ubuntu** `tracee-make` environment.

> **Note**: compiling `tracee-rules` with STATIC=1 won't allow you to use
> golang based signatures:
>
> ```
> 2021/12/13 13:27:21 error opening plugin /tracee/dist/rules/builtin.so: plugin.Open("/tracee/dist/rules/builtin.so"): Dynamic loading not supported
> ```

### Running `tracee-make` as the MAKE tool

You may also want to execute the **tracee-make** docker container as a
replacement to the `make` command:

```
$ make -f builder/Makefile.docker xxxx-make ARG="clean"
$ make -f builder/Makefile.docker xxxx-make ARG="bpf-core"
$ make -f builder/Makefile.docker xxxx-make ARG="tracee-ebpf"
```

And even tell **tracee-make** to do STATIC builds:

```
$ STATIC=0 make -f builder/Makefile.docker xxxx-make ARG="tracee-ebpf"
$ STATIC=1 make -f builder/Makefile.docker xxxx-make ARG="tracee-ebpf"
```

> where xxxx might be 'alpine' or 'ubuntu'

## More information

Read [MORE](README-containers.md) on how to use 'tracee-make' container.
