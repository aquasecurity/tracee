module github.com/aquasecurity/tracee

go 1.15

replace github.com/aquasecurity/tracee/libbpfgo => ./libbpfgo

require (
	github.com/aquasecurity/tracee/libbpfgo v0.0.0-00010101000000-000000000000
	github.com/iovisor/gobpf v0.0.0-20200529092446-49b58e11a4b5
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/urfave/cli/v2 v2.1.1
)
