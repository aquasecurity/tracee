package extensions

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

type ModulesPerExtension struct {
	mod   map[string]*bpf.Module // [extension_name]bpf_module
	mutex *sync.Mutex
}

func (m *ModulesPerExtension) Set(ext string, mod *bpf.Module) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.mod[ext] = mod
}

func (m *ModulesPerExtension) Get(ext string) *bpf.Module {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.mod[ext]
}

func (m *ModulesPerExtension) GetOk(ext string) (*bpf.Module, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	mod, ok := m.mod[ext]
	return mod, ok
}

func (m *ModulesPerExtension) IsDefined(ext string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, ok := m.mod[ext]
	return ok
}

func (m *ModulesPerExtension) Close(ext string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if mod, ok := m.mod[ext]; ok {
		if mod != nil {
			mod.Close()
		}
	}
	delete(m.mod, ext)
}
