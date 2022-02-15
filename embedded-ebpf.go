//go:build ebpf
// +build ebpf

package ebpf

import (
	"embed"
)

//go:embed "dist/tracee.bpf.core.o"
//go:embed "dist/btfhub/*"

var BPFBundleInjected embed.FS
