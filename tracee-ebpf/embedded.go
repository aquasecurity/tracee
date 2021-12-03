package tracee_ebpf

import (
	"embed"
)

//go:embed "dist/tracee.bpf/*"
//go:embed "dist/tracee.bpf.core.o"
var BPFBundleInjected embed.FS
