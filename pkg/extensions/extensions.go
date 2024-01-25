package extensions

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

var Modules *ModulesPerExtension

func init() {
	Modules = &ModulesPerExtension{
		mod:   map[string]*bpf.Module{},
		mutex: &sync.Mutex{},
	}
}
