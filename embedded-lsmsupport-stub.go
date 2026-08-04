//go:build lsmsupport && ebpfstub

package tracee

import (
	"embed"
)

// Empty stand-in for static analysis and unit tests: with the ebpfstub tag
// nothing is embedded, so compilation does not require the built LSM support
// objects in dist/. Real builds never set the tag.
var LSMBundleInjected embed.FS
