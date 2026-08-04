//go:build ebpf && ebpfstub

package tracee

import (
	"embed"
)

// Empty stand-in for static analysis and unit tests: with the ebpfstub tag
// nothing is embedded, so compilation does not require the built BPF object
// and btfhub artifacts in dist/. Real builds never set the tag.
var BPFBundleInjected embed.FS
