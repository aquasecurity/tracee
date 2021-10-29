module github.com/aquasecurity/tracee/tracee-ebpf

go 1.16

replace github.com/aquasecurity/tracee/tracee-ebpf/external => ./external/

require (
	github.com/aquasecurity/libbpfgo v0.2.1-libbpf-0.4.0.0.20210910045113-64a32faceb3c
	github.com/aquasecurity/tracee/tracee-ebpf/external v0.0.0-20210922213431-07969faccea0
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/gopacket v1.1.19
	github.com/hashicorp/golang-lru v0.5.4
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/net v0.0.0-20210825183410-e898025ed96a // indirect
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	inet.af/netaddr v0.0.0-20210903134321-85fa6c94624e
)
