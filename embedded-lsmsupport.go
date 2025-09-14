//go:build lsmsupport
// +build lsmsupport

package tracee

import (
	"embed"
)

//go:embed "dist/lsm_support/*"
var LSMBundleInjected embed.FS
