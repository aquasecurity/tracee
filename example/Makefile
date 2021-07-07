build:
	GOOS=linux GOARCH=amd64 CC=clang CGO_CFLAGS="-I /usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/usr/include" CGO_LDFLAGS="/usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/libbpf.a" go build -tags=opa_wasm -o tracee-lib-example main.go

clean:
	rm -rf tracee-lib-example

run:
	sudo GOOS=linux GOARCH=amd64 CC=clang CGO_CFLAGS="-I /usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/usr/include" CGO_LDFLAGS="/usr/vagrant/repos/tracee/tracee-ebpf/dist/libbpf/libbpf.a" ./tracee-lib-example