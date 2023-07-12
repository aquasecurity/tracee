# Creating a local building environment

> These instructions are meant to describe how to create a local building and
> execution environment. If you would like to build tracee container(s)
> image(s), [read this](./containers.md) instead.

!!! Note
    A building environment will let you build and execute tracee inside a docker
    container, containing all needed tools to build and execute it. If you're
    using an OSX environment, for example, you can install gmake (`brew install
    gmake`) and configure such environment by using Docker.

!!! Attention
    If you want to build tracee on your local machine
    [read this](./building.md).


## Quick steps (**impatient readers**)

!!! Example

    * Build and execute **tracee**:
    
        ```console
        make -f builder/Makefile.tracee-make alpine-prepare
        make -f builder/Makefile.tracee-make alpine-shell
        ```

        and inside the container:

        ```console
        make clean
        make tracee
        sudo ./dist/tracee \
            -o option:parse-arguments \
            --scope comm=bash \
            --scope follow
        ```
    
    Now, in your host's bash shell, execute a command. You will see all events
    (except scheduler ones) being printed, in "table format", to stdout.
    
    * Build and execute **tracee**:
    
        ```console
        make -f builder/Makefile.tracee-make alpine-prepare
        make -f builder/Makefile.tracee-make alpine-shell
        ```

        and inside the container:

        ```console
        make clean
        make all
        sudo ./dist/tracee \
            -o format:json \
            -o option:parse-arguments \
            --scope comm=bash \
            --scope follow 
        ```
    
    Now, in your host's bash shell, execute: `sudo strace /bin/ls` and observe
    tracee warning you about a possible risk (with its Anti-Debugging signature).

Now, for **more patient readers** ...

## How to build and use the environment

In order to have a controlled building environment for tracee, tracee provides
a `Makefile.tracee-make` file that allows you to create and use a docker
container environment to build & test **tracee**. 

Two different environments are maintained for building tracee:

* Alpine
* Ubuntu

The reason for that is that **Alpine Linux** is based in the
[musl](https://en.wikipedia.org/wiki/Musl) C standard library, while the
**Ubuntu Linux** uses [glibc](https://en.wikipedia.org/wiki/Glibc). By
supporting both building environments we can always be sure that the project
builds (and executes) correctly in both environments.

!!! Attention
    Locally created containers, called `alpine-tracee-make` or
    `ubuntu-tracee-make`, share the host source code directory. This means
    that, if you build tracee binary using `alpine` distribution, the binary
    might not be compatible to the Linux distribution from your host OS.

### Creating a builder environment

* To create an **alpine-tracee-make** container:

    ```console
    make -f builder/Makefile.tracee-make alpine-prepare
    ```

* To create an **ubuntu-tracee-make** container:

    ```console
    make -f builder/Makefile.tracee-make ubuntu-prepare
    ```

### Executing a builder environment

* To execute an **alpine-tracee-make** shell:

    ```console
    make -f builder/Makefile.tracee-make alpine-shell
    ```

* To execute an **ubuntu-tracee-make** shell:

    ```console
    make -f builder/Makefile.tracee-make ubuntu-shell
    ```

### Using build environment as a **make** replacement

Instead of executing a builder shell, you may use `alpine-tracee-make`, or
`ubuntu-tracee-make`, as a replacement for the `make` command:

```console
make -f builder/Makefile.tracee-make ubuntu-prepare
make -f builder/Makefile.tracee-make ubuntu-make ARG="help"
make -f builder/Makefile.tracee-make ubuntu-make ARG="clean"
make -f builder/Makefile.tracee-make ubuntu-make ARG="bpf"
make -f builder/Makefile.tracee-make ubuntu-make ARG="tracee"
make -f builder/Makefile.tracee-make ubuntu-make ARG="all"
```

And, after the compilation, run the commands directly in your host:

```console
sudo ./dist/tracee \
    -o option:parse-arguments \
    --scope comm=bash \
    --scope follow
```

> **Note**: the generated binary must be compatible to your host (depending on
> glibc version, for example).

If you don't want to depend on host's libraries versions, or if you are using
the `alpine-tracee-make` container as a replacement for `make`, and your host
is not an **Alpine Linux**, then you may set `STATIC=1` variable so you can run
compiled binaries in your host:

```console
make -f builder/Makefile.tracee-make alpine-prepare
make -f builder/Makefile.tracee-make alpine-make ARG="help"
STATIC=1 make -f builder/Makefile.tracee-make alpine-make ARG="all"
```

and execute the static binary from your host:

```console
ldd dist/tracee
```

```text
not a dynamic executable
```

!!! Attention
    compiling **tracee-rules** with STATIC=1 won't allow you to use golang based
    signatures:
    > ```text
    > 2021/12/13 13:27:21 error opening plugin /tracee/dist/signatures/builtin.so:
    > plugin.Open("/tracee/dist/signatures/builtin.so"): Dynamic loading not supported
    > ```
