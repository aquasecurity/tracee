package lsmsupport

import (
	embed "github.com/aquasecurity/tracee"
)

// loadBPFObjectBytes loads BPF object file from embedded filesystem
func loadBPFObjectBytes(objectName string) ([]byte, error) {
	return embed.LSMBundleInjected.ReadFile("dist/lsm_support/" + objectName)
}
