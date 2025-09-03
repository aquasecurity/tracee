package environment

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/common/logger"
)

var (
	ErrSecurityFSNotMounted = errors.New("security filesystem not mounted (CONFIG_SECURITY likely disabled)")
	ErrProcFSNotAvailable   = errors.New("proc filesystem not available (CONFIG_PROC_FS disabled or not mounted)")
)

// CheckLSMSupport checks if BPF LSM is supported using runtime securityfs detection with kernel config fallback.
// It first attempts runtime detection, falling back to kernel config if securityfs is not mounted.
func CheckLSMSupport(filesystem fs.FS, getKernelConfigValue KernelConfigValueFunc) (bool, error) {
	// Check runtime LSM enablement using the provider's filesystem
	runtimeEnabled, err := IsLSMSupportedInSecurityFs(filesystem)
	if err != nil {
		// If security fs is not mounted, fall back to kernel config check
		if errors.Is(err, ErrSecurityFSNotMounted) {
			return CheckBPFLSMConfigSupport(getKernelConfigValue, filesystem)
		}
		return false, err
	}

	return runtimeEnabled, nil
}

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

// CheckBPFLSMInKernelConfig checks if CONFIG_BPF_LSM is enabled in kernel configuration.
// Returns true if BPF LSM is compiled into the kernel.
func CheckBPFLSMInKernelConfig(getKernelConfigValue KernelConfigValueFunc) (bool, error) {
	bpfLsmType, _, err := getKernelConfigValue(CONFIG_BPF_LSM)
	if err != nil {
		return false, err
	}
	if bpfLsmType != BUILTIN {
		return false, errors.New("BPF_LSM is not builtin")
	}
	return true, nil
}

// CheckBPFInKernelConfigLSM checks if 'bpf' is present in CONFIG_LSM kernel configuration.
// Returns true if CONFIG_LSM contains "bpf", false if not present, error if CONFIG_LSM is malformed.
func CheckBPFInKernelConfigLSM(getKernelConfigValue KernelConfigValueFunc) (bool, error) {
	lsmType, lsmString, err := getKernelConfigValue(CONFIG_LSM)
	if err != nil {
		// CONFIG_LSM not set - not an error, just means no default
		return false, nil
	}

	// If CONFIG_LSM is UNDEFINED (not set), that's fine
	if lsmType == UNDEFINED {
		return false, nil
	}

	// Parse CONFIG_LSM value and check for 'bpf'
	if lsmType != STRING {
		return false, errors.New("CONFIG_LSM is not a string")
	}

	lsmModules := strings.Split(lsmString, ",")
	for _, module := range lsmModules {
		if strings.TrimSpace(module) == "bpf" {
			return true, nil
		}
	}

	return false, nil
}

// CheckBPFLSMConfigSupport determines whether the Linux Security Module (LSM) framework is enabled
// and supports BPF modules on the current system, based on kernel configuration and boot parameters.
func CheckBPFLSMConfigSupport(getKernelConfigValue KernelConfigValueFunc, filesystem fs.FS) (bool, error) {
	// First check if CONFIG_BPF_LSM is enabled (required)
	bpfSupported, err := CheckBPFLSMInKernelConfig(getKernelConfigValue)
	if err != nil {
		return false, err
	}
	if !bpfSupported {
		return false, errors.New("BPF_LSM is not builtin")
	}

	// Check boot parameters for LSM configuration
	bootResult, err := CheckBPFInBootParams(filesystem)
	if err != nil {
		// Error reading boot params, fallback to kernel config
		logger.Debugw("Failed to check BPF in boot params", "error", err)
	} else if bootResult.ParameterFound {
		// Boot parameters explicitly set LSM list - this takes full precedence
		// Return the boot parameter result regardless of BPF enabled/disabled
		return bootResult.BPFEnabled, nil
	}

	// No LSM boot parameter found, fallback to checking CONFIG_LSM kernel configuration
	configEnabled, err := CheckBPFInKernelConfigLSM(getKernelConfigValue)
	if err != nil {
		return false, err
	}

	return configEnabled, nil
}

// GetBootOptionsFromFS parses all boot options from /proc/cmdline using provided filesystem
// Returns a map of boot parameters (key -> value, empty string for boolean params)
func GetBootOptionsFromFS(filesystem fs.FS) (map[string]string, error) {
	// Try to read proc/cmdline (relative path for fs.FS)
	cmdlineData, err := fs.ReadFile(filesystem, "proc/cmdline")
	if err != nil {
		// Handle specific error cases
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrProcFSNotAvailable
		}
		return nil, fmt.Errorf("failed to read proc/cmdline: %w", err)
	}

	cmdline := strings.TrimSpace(string(cmdlineData))
	if cmdline == "" {
		// No boot parameters present - return empty map
		return make(map[string]string), nil
	}

	// Parse boot options
	options := make(map[string]string)
	params := strings.Fields(cmdline)

	for _, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		// Split on first '=' to handle values that contain '='
		parts := strings.SplitN(param, "=", 2)

		if len(parts) == 1 {
			// Boolean parameter (no value) - existence is what matters
			options[parts[0]] = ""
		} else {
			// Key-value parameter
			options[parts[0]] = parts[1]
		}
	}

	return options, nil
}

const LsmBootOption = "lsm"
const BpfLsmModule = "bpf"

// LSMBootResult contains information about BPF LSM status in boot parameters
type LSMBootResult struct {
	BPFEnabled     bool // true if BPF is found in the lsm boot parameter
	ParameterFound bool // true if lsm= boot parameter exists (even if empty)
}

// CheckBPFInBootParams checks if BPF LSM is enabled in boot parameters using provided filesystem
// Returns LSMBootResult containing BPF status and whether the lsm parameter was found
func CheckBPFInBootParams(filesystem fs.FS) (LSMBootResult, error) {
	bootOptions, err := GetBootOptionsFromFS(filesystem)
	if err != nil {
		return LSMBootResult{}, err
	}

	// Look for 'lsm' parameter
	lsmValue, exists := bootOptions[LsmBootOption]
	if !exists {
		// No LSM parameter found - system will use defaults
		return LSMBootResult{BPFEnabled: false, ParameterFound: false}, nil
	}

	// LSM parameter exists (even if empty)
	result := LSMBootResult{ParameterFound: true}

	if lsmValue == "" {
		// Empty lsm parameter means no LSMs enabled via boot params
		result.BPFEnabled = false
		return result, nil
	}

	// Parse LSM list (comma-separated)
	lsmModules := strings.Split(lsmValue, ",")

	for _, module := range lsmModules {
		cleaned := strings.TrimSpace(module)
		if cleaned != "" {
			if cleaned == BpfLsmModule {
				result.BPFEnabled = true
				return result, nil
			}
		}
	}

	result.BPFEnabled = false
	return result, nil
}

// GetBootOptions is a convenience function that uses the OS filesystem.
// It is recommended to use GetBootOptionsFromFS instead to increase testability.
func GetBootOptions() (map[string]string, error) {
	return GetBootOptionsFromFS(os.DirFS("/"))
}

// CheckBPFInBootParamsOS is a convenience function that uses the OS filesystem.
// It is recommended to use CheckBPFInBootParams(fs.FS) instead to increase testability.
func CheckBPFInBootParamsOS() (LSMBootResult, error) {
	return CheckBPFInBootParams(os.DirFS("/"))
}

// CheckBPFInBootParamsEnabled is a convenience function that returns only the BPF enabled status
// for backward compatibility. It uses the OS filesystem.
func CheckBPFInBootParamsEnabled() (bool, error) {
	result, err := CheckBPFInBootParams(os.DirFS("/"))
	return result.BPFEnabled, err
}
