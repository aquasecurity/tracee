`libbpfgo` is using CGO to interop with `libbpf` and will expect to be linked with `libbpf` at run or link time. Simply importing `libbpfgo` is not enough to get started, and you will need to fulfill the required dependency in one of the following ways:

1. Install the `libbpf` as a shared object in the system. `libbpf` may already be packaged for you distribution, if not, you can build and install from source. More info [here](https://github.com/`libbpf`/`libbpf`).
2. Embed `libbpf` into your Go project as a vendored dependency. This means that the `libbpf` code is statically linked into the resulting binary, and there are no runtime dependencies. Tracee takes this approach and you can take example from it's [Makefile](https://github.com/aquasecurity/tracee/blob/main/Makefile).
