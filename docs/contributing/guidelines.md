## Style Guide for Contributors

For those willing to contribute to Tracee, this repository has code formatting
guidelines being enforced. It is recommended that, before commiting your
changes, you run the following command:

1. Check for formatting issues

!!! check-fmt Example

    ```
    $ make check-fmt
    Checking C and eBPF files and headers formatting...
    Checking golang files formatting...
    ```
    
    > This will make sure PRs won't fail due to same checks being enforced.

2. Fix Go and C source files formatting

!!! fix-fmt Example

    ```
    $ make fix-fmt
    
    Fixing C and eBPF files and headers formatting...
    Formatting ./pkg/ebpf/c/missing_definitions.h
    Formatting ./pkg/ebpf/c/struct_flavors.h
    Formatting ./pkg/ebpf/c/tracee.bpf.c
    Formatting ./pkg/ebpf/c/vmlinux.h
    
    Fixing golang files formatting...
    patching file pkg/ebpf/tracee.go
    
    $ git status -s
     M Makefile
     M builder/Makefile.checkers
     M pkg/ebpf/c/missing_definitions.h
     M pkg/ebpf/c/struct_flavors.h
     M pkg/ebpf/c/tracee.bpf.c
     M pkg/ebpf/c/vmlinux.h
    ```

3. Static Check Go and C source files


!!! check-code Example

    ```
    $ make check-code
    
    Checking Golang vet...
    make[2]: warning: jobserver unavailable: using -j1.  Add '+' to parent make rule.
    GOOS=linux CC=clang GOARCH=amd64 CGO_CFLAGS="-I/home/rafaeldtinoco/work/ebpf/tracee-review/dist/libbpf" CGO_LDFLAGS="-lelf -lz /home/rafaeldtinoco/work/ebpf/tracee-review/dist/libbpf/libbpf.a" \
    go vet \
    	-tags core,ebpf \
    	./...
    
    Checking Golang with StaticChecker...
    make[2]: warning: jobserver unavailable: using -j1.  Add '+' to parent make rule.
    GOOS=linux CC=clang GOARCH=amd64 CGO_CFLAGS="-I/home/rafaeldtinoco/work/ebpf/tracee-review/dist/libbpf" CGO_LDFLAGS="-lelf -lz /home/rafaeldtinoco/work/ebpf/tracee-review/dist/libbpf/libbpf.a" \
    staticcheck -f stylish \
    	-tags core,ebpf \
    	./...
     ✖ 0 problems (0 errors, 0 warnings, 0 ignored)

     Checking Golang with errcheck...
    ```
