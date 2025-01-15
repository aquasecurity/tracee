# Building from the source

!!! Note
    Consider also visiting the following instructions:  
    1. docker container as [building environment](./environment.md)  
    2. building tracee [container images](./containers.md)  

1. Supported **Architectures**

    1. x86_64 (amd64)
    1. aarch64 (arm64)

2. Building **dependencies**

    1. `clang` && `llvm` (14)
    2. `golang` (1.22.3 toolchain)
    3. `libelf` and `libelf-dev`
       (or elfutils-libelf and elfutils-libelf-devel)
    4. `zlib1g` and `zlib1g-dev`
       (or zlib and zlib-devel)
    5. `libzstd-dev` for static build (libelf linkage)
    6. `clang-format-12` (specific version) for `fix-fmt`

    > You might take a look at the following files to understand how to have a
    > building environment:
    >
    > 1. [.github/actions/build-dependencies/action.yaml](https://github.com/aquasecurity/tracee/blob/main/.github/actions/build-dependencies/action.yaml)
    > 1. [builder/Dockerfile.ubuntu-tracee-make](https://github.com/aquasecurity/tracee/blob/main/builder/Dockerfile.ubuntu-tracee-make)
    > 1. [builder/Dockerfile.alpine-tracee-make](https://github.com/aquasecurity/tracee/blob/main/builder/Dockerfile.alpine-tracee-make)
    >
    > Those are very good examples for you to replicate a working environment.

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

        $ make all                      # build tracee-ebpf, tracee-rules & signatures
        $ make bpf                      # build ./dist/tracee.bpf.o
        $ make tracee-ebpf              # build ./dist/tracee-ebpf
        $ make tracee-rules             # build ./dist/tracee-rules
        $ make tracee-bench             # build ./dist/tracee-bench
        $ make signatures               # build ./dist/signatures
        $ make e2e-net-signatures       # build ./dist/e2e-net-signatures
        $ make e2e-inst-signatures      # build ./dist/e2e-inst-signatures
        $ make tracee                   # build ./dist/tracee
        $ make tracee-operator          # build ./dist/tracee-operator

    # clean

        $ make clean                    # wipe ./dist/
        $ make clean-bpf                # wipe ./dist/tracee.bpf.o
        $ make clean-tracee-ebpf        # wipe ./dist/tracee-ebpf
        $ make clean-tracee-rules       # wipe ./dist/tracee-rules
        $ make clean-tracee-bench       # wipe ./dist/tracee-bench
        $ make clean-signatures         # wipe ./dist/signatures
        $ make clean-tracee             # wipe ./dist/tracee
        $ make clean-tracee-operator    # wipe ./dist/tracee-operator

    # test

        $ make test-unit                # run unit tests
        $ make test-types               # run unit tests for types module
        $ make test-integration         # run integration tests

    # flags

        $ STATIC=1 make ...             # build static binaries
        $ BTFHUB=1 STATIC=1 make ...    # build static binaries, embed BTF
        $ DEBUG=1 make ...              # build binaries with debug symbols
        $ METRICS=1 make ...            # build enabling BPF metrics

    ```

5. Build **all** targets at once

    ```bash
    make all
    ```

6. Build a **static binary** by setting `STATIC=1`

    ```bash
    STATIC=1 make all
    ```

7. Build a **static binary** with [BTFHUB Support](https://github.com/aquasecurity/btfhub)

    ```bash
    BTFHUB=1 STATIC=1 make all
    ```

    !!! Note
        BTFHUB support will embed several very small files (BTF files) into your
        final binary. Those files will allow **tracee** binary to be executed
        in kernels that doesn't have embedded BTF information (the ones described
        at the BTFHUB repository)

    !!! Attention
        compiling `tracee-rules` with STATIC=1 won't allow you to use golang based
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
