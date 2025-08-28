package environment

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

var (
	ErrSecurityFSNotMounted = errors.New("security filesystem not mounted (CONFIG_SECURITY likely disabled)")
)

// IsLSMSupportedInSecurityFs checks if BPF is enabled in the LSM framework by reading securityfs.
// It first checks if /sys/kernel/security exists, then parses the LSM file for 'bpf' entry.
func IsLSMSupportedInSecurityFs(filesystem fs.FS) (bool, error) {
	// First check if security filesystem is mounted
	securityDir := "sys/kernel/security"
	if _, err := fs.Stat(filesystem, securityDir); errors.Is(err, fs.ErrNotExist) {
		return false, ErrSecurityFSNotMounted
	} else if err != nil {
		return false, fmt.Errorf("failed to access %s: %w", securityDir, err)
	}

	// Check LSM file
	lsmFile := "sys/kernel/security/lsm"
	data, err := fs.ReadFile(filesystem, lsmFile)
	if errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("LSM file not found: %s", lsmFile)
	} else if err != nil {
		return false, fmt.Errorf("failed to read %s: %v", lsmFile, err)
	}

	// Parse LSM list and check for 'bpf'
	lsmList := strings.TrimSpace(string(data))
	lsmModules := strings.Split(lsmList, ",")

	for _, module := range lsmModules {
		if strings.TrimSpace(module) == "bpf" {
			return true, nil
		}
	}

	return false, nil
}

// IsBPFEnabledInLSMFromOS is a convenience function that uses the OS filesystem.
// It is recommended to use IsLSMSupportedInSecurityFs instead to increase testability.
func IsBPFEnabledInLSMFromOS() (bool, error) {
	return IsLSMSupportedInSecurityFs(os.DirFS("/"))
}

// KernelConfigValueFunc is a function type for retrieving kernel configuration values.
// This allows for abstraction of kernel config access for testing purposes.
type KernelConfigValueFunc func(option KernelConfigOption) (KernelConfigOptionValue, string, error)

// CheckLSMSupportInKconfig checks if BPF LSM is supported by examining kernel configuration.
// It verifies CONFIG_BPF_LSM=y and that 'bpf' is present in CONFIG_LSM.
func CheckLSMSupportInKconfig(getKernelConfigValue KernelConfigValueFunc) (bool, error) {
	// First check if CONFIG_BPF_LSM is enabled
	bpfLsmType, _, err := getKernelConfigValue(CONFIG_BPF_LSM)
	if err != nil {
		return false, err
	}
	if bpfLsmType != BUILTIN {
		return false, errors.New("BPF_LSM is not builtin")
	}

	// Then check if 'bpf' is in CONFIG_LSM
	lsmType, lsmString, err := getKernelConfigValue(CONFIG_LSM)
	if err != nil {
		// CONFIG_LSM not set - BPF LSM not supported
		return false, errors.New("CONFIG_LSM is not set")
	}

	// Parse CONFIG_LSM value and check for 'bpf'
	if lsmType != STRING {
		// CONFIG_LSM is not a string - BPF LSM not supported
		return false, errors.New("CONFIG_LSM is not a string")
	}

	lsmModules := strings.Split(lsmString, ",")
	for _, module := range lsmModules {
		if strings.TrimSpace(module) == "bpf" {
			return true, nil
		}
	}

	// CONFIG_BPF_LSM=y but 'bpf' not in CONFIG_LSM list
	return false, errors.New("BPF is not in LSM list")
}

// CheckLSMSupport checks if BPF LSM is supported using runtime securityfs detection with kernel config fallback.
// It first attempts runtime detection, falling back to kernel config if securityfs is not mounted.
func CheckLSMSupport(filesystem fs.FS, getKernelConfigValue KernelConfigValueFunc) (bool, error) {
	// Check runtime LSM enablement using the provider's filesystem
	runtimeEnabled, err := IsLSMSupportedInSecurityFs(filesystem)
	if err != nil {
		// If security fs is not mounted, fall back to kernel config check
		if errors.Is(err, ErrSecurityFSNotMounted) {
			return CheckLSMSupportInKconfig(getKernelConfigValue)
		}
		return false, err
	}

	return runtimeEnabled, nil
}
