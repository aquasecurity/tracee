# Building from the source (host toolchain)

!!! Note
    By default `make` runs every target inside the containerized
    [building environment](./environment.md) - no host toolchain needed.
    This page describes the `NATIVE=1` escape hatch for building with your
    host's own toolchain. Consider also:  
    1. the containerized [building environment](./environment.md) (default)  
    2. building tracee [container images](./containers.md)  
    3. using [development images](./containers.md#development-images) for testing latest changes  

1. Supported **Architectures**

    1. x86_64 (amd64)
    1. aarch64 (arm64)

2. Building **dependencies**

    1. `clang` && `llvm` (19)
    2. `golang` (1.26.5 toolchain)
    3. `libelf` and `libelf-dev`
       (or elfutils-libelf and elfutils-libelf-devel)
    4. `zlib1g` and `zlib1g-dev`
       (or zlib and zlib-devel)
    5. `libzstd-dev` for static build (libelf linkage)
    6. `clang-format-19` (specific version) for `fix-fmt`

    > Take a look at the following files to understand how to replicate a
    > working environment:
    >
    > 1. [builder/Containerfile](https://github.com/aquasecurity/tracee/blob/main/builder/Containerfile)
    > 1. [scripts/installation/](https://github.com/aquasecurity/tracee/tree/main/scripts/installation)
    >
    > They are the source of truth for the toolchain and its versions.

3. **Clone** [tracee repository](https://github.com/aquasecurity/tracee/)

    ```bash
    git clone [https://github.com/aquasecurity/tracee/](https://github.com/aquasecurity/tracee/)
    ```

4. All makefiles have a **help** target to give you needed instructions

    ```bash
    make help
    ```

    ```text
    # environment

        $ make env                      # show makefile environment/variables

    # build

        $ make all                      # build tracee, signatures & other tools
        $ make bpf                      # build ./dist/tracee.bpf.o
        $ make tracee                   # build ./dist/tracee
        $ make tracee-bench             # build ./dist/tracee-bench
        $ make signatures               # build ./dist/signatures
        $ make tracee-operator          # build ./dist/tracee-operator

    # clean

        $ make clean                    # wipe ./dist/
        $ make clean-bpf                # wipe ./dist/tracee.bpf.o
        $ make clean-tracee             # wipe ./dist/tracee
        $ make clean-tracee-bench       # wipe ./dist/tracee-bench
        $ make clean-signatures         # wipe ./dist/signatures
        $ make clean-tracee-operator    # wipe ./dist/tracee-operator

    # test

        $ make test-unit                # run unit tests
        $ make test-types               # run unit tests for types module
        $ make test-common              # run unit tests for common module
        $ make test-integration         # run integration tests

    # flags

        $ STATIC=1 make ...             # build static binaries
        $ BTFHUB=1 STATIC=1 make ...    # build static binaries, embed BTF
        $ DEBUG=1 make ...              # build binaries with debug symbols
        $ METRICS=1 make ...            # build enabling BPF metrics

    ```

5. Build **all** targets at once with the host toolchain

    ```bash
    NATIVE=1 make all
    ```

    !!! Note
        Without `NATIVE=1` the build runs inside the containerized build
        environment - which is fine too, and needs none of the dependencies
        above. All examples below accept the same flag.

6. Build a **static binary** by setting `STATIC=1`

    ```bash
    NATIVE=1 STATIC=1 make all
    ```

7. Build a **static binary** with [BTFHUB Support](https://github.com/aquasecurity/btfhub)

    ```bash
    NATIVE=1 BTFHUB=1 STATIC=1 make all
    ```

    !!! Note
        BTFHUB support will embed several very small files (BTF files) into your
        final binary. Those files will allow **tracee** binary to be executed
        in kernels that doesn't have embedded BTF information (the ones described
        at the BTFHUB repository)

    !!! Attention
        compiling with STATIC=1 won't allow you to use golang based
        signatures as plugins, only as built-ins:
        >```text
        >2021/12/13 13:27:21 error opening plugin /tracee/dist/signatures/builtin.so:
        >plugin.Open("/tracee/dist/signatures/builtin.so"): Dynamic loading not supported
        >```

8. Build a **debuggable binary** with DWARF debug symbols by setting `DEBUG=1`

    ```bash
    DEBUG=1 make
    ```

9. Build enabling BPF metrics by setting `METRICS=1`

    BPF metrics are only available if the BPF object is built with `METRICS` debug flag defined.

    ```bash
    METRICS=1 make
    ```

## Development Images

See the development images, usage examples, and stability guidance in the container images guide: [Development Images](./containers.md#development-images).
