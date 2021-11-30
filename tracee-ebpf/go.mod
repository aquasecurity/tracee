module github.com/aquasecurity/tracee/tracee-ebpf

go 1.16

replace github.com/aquasecurity/tracee/tracee-ebpf/external => ./external/

require (
	github.com/aquasecurity/libbpfgo v0.2.2-libbpf-0.5.0
	github.com/aquasecurity/tracee/tracee-ebpf/external v0.0.0-20210903145311-dfdb5d66613f
	github.com/google/gopacket v1.1.19
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
	inet.af/netaddr v0.0.0-20210903134321-85fa6c94624e
	github.com/hashicorp/golang-lru v0.5.4
)
