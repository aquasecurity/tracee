//go:build ebpf && !ebpfstub

package tracee

import (
	"embed"
)

//go:embed "dist/tracee.bpf.o"
//go:embed "dist/btfhub/*"

var BPFBundleInjected embed.FS
