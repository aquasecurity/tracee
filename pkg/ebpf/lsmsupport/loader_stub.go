//go:build !lsmsupport

package lsmsupport

import (
	"errors"
)

// loadBPFObjectBytes is a stub implementation when lsmsupport build tag is not present
// This allows the package to compile without requiring the embedded LSM BPF objects
func loadBPFObjectBytes(objectName string) ([]byte, error) {
	return nil, errors.New("LSM BPF objects not embedded - compile with -tags lsmsupport to enable LSM support")
}
