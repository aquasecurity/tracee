//go:build lsmsupport && !ebpfstub

package tracee

import (
	"embed"
)

//go:embed "dist/lsm_support/*"
var LSMBundleInjected embed.FS
