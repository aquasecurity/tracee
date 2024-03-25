package ksymbols

import (
	"fmt"
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
)

var (
	instance *helpers.KernelSymbolTable
	once     sync.Once
)

// GetInstance lazily initializes and returns the singleton instance of KernelSymbolTable.
// It ensures that the instance is created only once, even in concurrent scenarios.
// If initialization fails, it returns nil and the error encountered during initialization.
func GetInstance() (*helpers.KernelSymbolTable, error) {
	var instanceErr error

	once.Do(func() {
		var kst *helpers.KernelSymbolTable

		err := capabilities.GetInstance().Specific(func() error {
			var innerErr error
			kst, innerErr = helpers.NewKernelSymbolTable()
			if innerErr != nil {
				return fmt.Errorf("failed to create new kernel symbol table: %w", innerErr)
			}

			return nil
		}, cap.SYSLOG)
		if err != nil {
			instanceErr = fmt.Errorf("failed to initialize kernel symbols: %w", err)
			return // early return from the Once.Do block
		}

		instance = kst
	})

	return instance, instanceErr
}

