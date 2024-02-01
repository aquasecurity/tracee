package global

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func init() {
}

var KSymbols *helpers.KernelSymbolTable

func init() {
	var err error
	err = capabilities.GetInstance().Specific(
		func() error {
			KSymbols, err = helpers.NewKernelSymbolTable()
			return err
		},
		cap.SYSLOG,
	)
	if err != nil {
		logger.Debugw("failed to initialize kernel symbols", "error", err)
	}
}
