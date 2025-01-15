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

## Quick steps

1. Build tracee environment:

    ```bash
    make -f builder/Makefile.tracee-make alpine-prepare
    make -f builder/Makefile.tracee-make alpine-shell
    ```

2. Build and execute tracee:

    ```bash
    make clean
    make tracee
    sudo ./dist/tracee \
        -o option:parse-arguments \
        --scope comm=bash \
        --scope follow
    ```

Now, in your host's shell, execute a command. You will see all events
(except scheduler ones) being printed, in "table format", to stdout.

## How to build and use the environment

In order to have a controlled building environment for tracee, tracee provides
a `Makefile.tracee-make` file that allows you to create and use a docker container environment to build & test **tracee**.

There are Two different environments that are maintained for building tracee:

* **Alpine**
* **Ubuntu**

The reason for that is that `Alpine Linux` is based in the [musl](https://en.wikipedia.org/wiki/Musl) C standard library,
while the `Ubuntu Linux` uses [glibc](https://en.wikipedia.org/wiki/Glibc).

By supporting both building environments we can always be sure that the project builds (and executes) correctly in both environments.

!!! Attention
    Locally created containers, called `alpine-tracee-make` or
    `ubuntu-tracee-make`, share the host source code directory. This means
    that, if you build tracee binary using `alpine` distribution, the binary
    might not be compatible to the Linux distribution from your host OS.

### Creating a builder environment

* To create an **alpine-tracee-make** container:

    ```bash
    make -f builder/Makefile.tracee-make alpine-prepare
    ```

* To create an **ubuntu-tracee-make** container:

    ```bash
    make -f builder/Makefile.tracee-make ubuntu-prepare
    ```

### Executing a builder environment

* To execute an **alpine-tracee-make** shell:

    ```bash
    make -f builder/Makefile.tracee-make alpine-shell
    ```

* To execute an **ubuntu-tracee-make** shell:

    ```bash
    make -f builder/Makefile.tracee-make ubuntu-shell
    ```

### Using build environment as a **make** replacement

Instead of executing a builder shell, you may use `alpine-make`, or
`ubuntu-make`, as a replacement for the `make` command:

1. Create builder environment as described:
    [Creating a builder environment](#creating-a-builder-environment)
2. Compile tracee using `ubuntu-make`

    * Build tracee binary:

        ```bash
        make -f builder/Makefile.tracee-make ubuntu-make ARG="tracee"
        ```

    * Show available `ubuntu-make` commands:

        ```bash
        make -f builder/Makefile.tracee-make ubuntu-make ARG="help"
        ```

    * Remove tracee binary

        ```bash
        make -f builder/Makefile.tracee-make ubuntu-make ARG="clean"
        ```

    * Build binaries for all

        ```bash
        make -f builder/Makefile.tracee-make ubuntu-make ARG="all"
        ```

3. Run tracee binary

    ```bash
    sudo ./dist/tracee
    ```

> **Note**: the generated binary must be compatible to your host (depending on glibc version).

If you don't want to depend on host's libraries versions, or you are using the `alpine-make` container as a replacement for `make`, then it's necessary  to set `STATIC` variable to `1` so you can run compiled binaries in your host machine:

1. Compile tracee

    ```bash
    make -f builder/Makefile.tracee-make alpine-prepare
    STATIC=1 make -f builder/Makefile.tracee-make alpine-make ARG="all"
    ```

2. Verify the executable is static

    * Note: ldd prints the shared libraries required by an executable file

    ```bash
    ldd dist/tracee
    ```

    ```text
    not a dynamic executable
    ```

3. Execute the static binary from your host

    ```bash
    sudo ./dist/tracee
    ```
