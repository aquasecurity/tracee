package extensions

import (
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

type ModulesPerExtension struct {
	modules map[string]*bpf.Module // [extension_name]bpf_module
	mutex   *sync.RWMutex
}

func (m *ModulesPerExtension) Set(ext string, mod *bpf.Module) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.modules[ext] = mod
}

func (m *ModulesPerExtension) Get(ext string) *bpf.Module {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.modules[ext]
}

func (m *ModulesPerExtension) GetOk(ext string) (*bpf.Module, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	mod, ok := m.modules[ext]
	return mod, ok
}

func (m *ModulesPerExtension) GetAll() []*bpf.Module {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	var mods []*bpf.Module
	for _, mod := range m.modules {
		mods = append(mods, mod)
	}
	return mods
}

func (m *ModulesPerExtension) IsDefined(ext string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	_, ok := m.modules[ext]
	return ok
}

func (m *ModulesPerExtension) Close(ext string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if mod, ok := m.modules[ext]; ok {
		if mod != nil {
			mod.Close()
		}
	}
	delete(m.modules, ext)
}
