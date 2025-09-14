// Package lsmsupport provides LSM BPF support detection by actually loading and testing a BPF LSM program.
package lsmsupport

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/logger"
)

var (
	lsmSupportCache    bool
	lsmSupportOnce     sync.Once
	lsmSupportCacheErr error
	loggerInitOnce     sync.Once
)

var ErrLoadBpfObjectFailed = errors.New("failed to load BPF object")
var ErrAttachProgramFailed = errors.New("failed to attach program")
var ErrInsufficientPrivileges = errors.New("insufficient privileges for BPF operations")

// setupLibbpfLogging configures libbpf to suppress verbose debug logs
// Only shows errors and warnings, similar to Tracee's approach
func setupLibbpfLogging() {
	loggerInitOnce.Do(func() {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(libLevel int, msg string) {
				// Only show errors and warnings, suppress info/debug
				// This matches the behavior users expect for a test utility
				switch libLevel {
				case bpf.LibbpfWarnLevel, bpf.LibbpfInfoLevel, bpf.LibbpfDebugLevel:
					// Suppress all non-error logs for cleaner output
					return
				default:
					// Show errors
					fmt.Fprintf(os.Stderr, "%s", msg)
				}
			},
		})
	})
}

// IsLsmBpfSupported checks if BPF LSM is supported by actually loading and testing a minimal LSM program.
// It returns true if LSM programs can be loaded and attached successfully, false otherwise.
// This is the definitive test for LSM support since it performs actual kernel operations.
// The result is cached to avoid repeated expensive BPF operations.
// To run this function, the LSM test BPF objects have to be built and embedded in the Tracee binary.
func IsLsmBpfSupported() (bool, error) {
	lsmSupportOnce.Do(func() {
		supported, err := isLsmBpfSupportedImpl()
		lsmSupportCache = supported
		lsmSupportCacheErr = err
	})

	return lsmSupportCache, lsmSupportCacheErr
}

// isLsmBpfSupportedImpl is the actual implementation that performs the BPF LSM test.
// It first tests kprobe BPF functionality as a sanity check, then tests LSM BPF support.
// This function is called only once by IsLsmBpfSupported thanks to sync.Once caching.
// Note: This function requires BPF capabilities to be set up.
func isLsmBpfSupportedImpl() (bool, error) {
	// Setup libbpf logging to suppress verbose debug output
	setupLibbpfLogging()

	// Check kprobe first (sanity check)
	supported, err := runCheckForModule("kprobe_check.bpf.o", "security_bpf_kprobe", "security_bpf", bpf.BPFProgTypeKprobe)
	if err != nil {
		return false, fmt.Errorf("kprobe sanity check failed with an error: %w", err)
	}

	if !supported {
		return false, errors.New("kprobe sanity check failed - BPF environment issue")
	}

	// Check LSM support
	supported, err = runCheckForModule("lsm_check.bpf.o", "lsm_bpf_check", "lsm_bpf", bpf.BPFProgTypeLsm)
	if err != nil {
		if errors.Is(err, ErrAttachProgramFailed) || errors.Is(err, ErrLoadBpfObjectFailed) {
			// Attachment and loading failures are signs of LSM not being supported in the system
			return false, nil
		}
		return false, fmt.Errorf("LSM support check failed with an error: %w", err)
	}

	return supported, nil
}

// runCheckForModule checks a single BPF program (LSM or kprobe) in isolation.
// It loads the program, attaches it, triggers it, and checks if the hook executed.
func runCheckForModule(objectName, programName, hookName string, progType bpf.BPFProgType) (bool, error) {
	// Load BPF object from dist directory (similar to Tracee main)
	moduleBytes, err := loadBPFObjectBytes(objectName)
	if err != nil {
		return false, fmt.Errorf("failed to read BPF object %s: %w", objectName, err)
	}

	module, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: moduleBytes,
	})
	if err != nil {
		if isPermissionError(err) {
			return false, fmt.Errorf("%w - %w", ErrInsufficientPrivileges, err)
		}
		return false, fmt.Errorf("failed to load BPF module: %w", err)
	}
	defer module.Close()

	// Load BPF program into kernel
	if err := module.BPFLoadObject(); err != nil {
		if isPermissionError(err) {
			return false, fmt.Errorf("%w - %w", ErrInsufficientPrivileges, err)
		}
		return false, fmt.Errorf("%w: %w", ErrLoadBpfObjectFailed, err)
	}

	// Get both programs
	prog, err := module.GetProgram(programName)
	if err != nil {
		return false, fmt.Errorf("failed to get program: %w", err)
	}

	// Initialize the result map
	resultMap, err := module.GetMap("check_result_map")
	if err != nil {
		return false, fmt.Errorf("failed to get result map: %w", err)
	}

	// Reset flag to false
	resultKey := uint32(0)
	initValue := uint8(0)
	if err := resultMap.Update(unsafe.Pointer(&resultKey), unsafe.Pointer(&initValue)); err != nil {
		return false, fmt.Errorf("failed to initialize result map: %w", err)
	}

	// Try to attach the program
	var link *bpf.BPFLink
	switch progType {
	case bpf.BPFProgTypeLsm:
		link, err = prog.AttachLSM()
	case bpf.BPFProgTypeKprobe:
		link, err = prog.AttachKprobe(hookName)
	}
	if err != nil {
		if isPermissionError(err) {
			return false, fmt.Errorf("%w - %w", ErrInsufficientPrivileges, err)
		}
		return false, fmt.Errorf("%w: %w", ErrAttachProgramFailed, err)
	}
	defer func() {
		if err := link.Destroy(); err != nil {
			logger.Warnw("failed to destroy link", "error", err)
		}
	}()

	// Get map value, which will also trigger the test program
	value0, err := resultMap.GetValue(unsafe.Pointer(&resultKey))
	if err != nil {
		return false, fmt.Errorf("failed to read result from BPF map: %w", err)
	}
	triggered := *(*uint8)(unsafe.Pointer(&value0[0])) == 1

	// LSM is supported if the LSM hook was triggered
	return triggered, nil
}

// isPermissionError checks if an error is related to insufficient privileges
// for BPF operations. This allows us to provide helpful error messages.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common permission-related syscall errors
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}

	// Check error message strings for BPF permission failures
	errStr := strings.ToLower(err.Error())
	permissionStrings := []string{
		"operation not permitted",
		"permission denied",
		"capability",
		"cap_",
		"requires root",
		"insufficient privileges",
	}

	for _, permStr := range permissionStrings {
		if strings.Contains(errStr, permStr) {
			return true
		}
	}

	return false
}
