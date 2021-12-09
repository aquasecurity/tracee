//go:build ebpf
// +build ebpf

package tracee

import (
	"embed"
)

//go:embed "dist/tracee.bpf/*"
//go:embed "dist/tracee.bpf.core.o"
var BPFBundleInjected embed.FS
