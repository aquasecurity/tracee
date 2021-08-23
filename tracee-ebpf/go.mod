module github.com/aquasecurity/tracee/tracee-ebpf

go 1.16

replace github.com/aquasecurity/tracee/tracee-ebpf/external => ./external/

require (
	github.com/aquasecurity/libbpfgo v0.1.2-0.20210823200145-0bbee70e5712
	github.com/aquasecurity/tracee/tracee-ebpf/external v0.0.0-20210727091827-bbe411a2a167
	github.com/google/gopacket v1.1.19
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015
	inet.af/netaddr v0.0.0-20210603230628-bf05d8b52dda
)
