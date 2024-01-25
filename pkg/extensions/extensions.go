package extensions

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

var Modules *ModulesPerExtension
var States *StatesPerExtension

func init() {
	Modules = &ModulesPerExtension{
		modules: map[string]*bpf.Module{},
		mutex:   &sync.Mutex{},
	}
	States = &StatesPerExtension{
		states: map[string]map[int]*EventState{},
		mutex:  &sync.RWMutex{},
	}
}
