package extensions

import (
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// Global
var KSymbols *helpers.KernelSymbolTable // global kernel symbol table

// Per Extension
var Modules *ModulesPerExtension         // eBPF modules
var States *StatesPerExtension           // event states
var Probes *ProbesPerExtension           // event probes
var Definitions *DefinitionsPerExtension // event definitions

// Global Initialization

func init() {
	var err error

	// Global and special initialization

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

	// Per-extension initialization

	Definitions = &DefinitionsPerExtension{
		definitions: map[string]map[int]Definition{},
		mutex:       &sync.RWMutex{},
	}
	Probes = &ProbesPerExtension{
		probes: map[string]map[int]Probe{},
		mutex:  &sync.RWMutex{},
	}
	States = &StatesPerExtension{
		states: map[string]map[int]*EventState{},
		mutex:  &sync.RWMutex{},
	}
	Modules = &ModulesPerExtension{
		modules: map[string]*bpf.Module{},
		mutex:   &sync.Mutex{},
	}
}

// Extensions Initialization (After Global Initialization)

func init() {
	// Core Extension
	initCore()
	//  Add more extension initializations here...
}
