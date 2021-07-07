How to run these benchmarks:
```
GOOS=linux GOARCH=amd64 CC=clang CGO_CFLAGS="-I /usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/usr/include" CGO_LDFLAGS="/usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/libbpf.a" go test -exec 'sudo -E' -v -bench=. -benchtime=1x -tags=opa_wasm 
```

Where:
CGO_FLAGS: Path to libbpf
CGO_LDFLAGS: Path to libbpf.a
