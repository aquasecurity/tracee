//go:build ebpf
// +build ebpf

package tracee

import (
	"embed"
)

//go:embed "dist/tracee.bpf.o"
//go:embed "dist/btfhub/*"

var BPFBundleInjected embed.FS
