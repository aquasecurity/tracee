package yaml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// Mock Registry

type mockRegistry struct {
	processStore      datastores.ProcessStore
	containerStore    datastores.ContainerStore
	systemStore       datastores.SystemStore
	kernelSymbolStore datastores.KernelSymbolStore
	dnsStore          datastores.DNSStore
	syscallStore      datastores.SyscallStore
}

func (m *mockRegistry) Processes() datastores.ProcessStore {
	return m.processStore
}

func (m *mockRegistry) Containers() datastores.ContainerStore {
	return m.containerStore
}

func (m *mockRegistry) System() datastores.SystemStore {
	return m.systemStore
}

func (m *mockRegistry) KernelSymbols() datastores.KernelSymbolStore {
	return m.kernelSymbolStore
}

func (m *mockRegistry) DNS() datastores.DNSStore {
	return m.dnsStore
}

func (m *mockRegistry) Syscalls() datastores.SyscallStore {
	return m.syscallStore
}

func (m *mockRegistry) GetCustom(name string) (datastores.DataStore, error) {
	return nil, datastores.ErrNotFound
}

func (m *mockRegistry) RegisterWritableStore(name string, store datastores.WritableStore) error {
	return nil // Mock implementation - not used in tests
}

func (m *mockRegistry) List() []string {
	return []string{}
}

func (m *mockRegistry) IsAvailable(name string) bool {
	return true
}

func (m *mockRegistry) GetMetadata(name string) (*datastores.DataStoreMetadata, error) {
	return nil, datastores.ErrNotFound
}

func (m *mockRegistry) GetMetrics(name string) (*datastores.DataStoreMetrics, error) {
	return nil, datastores.ErrNotFound
}

// Mock ProcessStore

type mockProcessStore struct {
	processes map[uint32]*datastores.ProcessInfo
}

func (m *mockProcessStore) Name() string {
	return "mock_process_store"
}

func (m *mockProcessStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockProcessStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockProcessStore) GetProcess(entityId uint32) (*datastores.ProcessInfo, error) {
	proc, ok := m.processes[entityId]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return proc, nil
}

func (m *mockProcessStore) GetChildProcesses(entityId uint32) ([]*datastores.ProcessInfo, error) {
	var children []*datastores.ProcessInfo
	for _, proc := range m.processes {
		if proc.Ppid == entityId {
			children = append(children, proc)
		}
	}
	return children, nil
}

func (m *mockProcessStore) GetAncestry(entityId uint32, maxDepth int) ([]*datastores.ProcessInfo, error) {
	var ancestry []*datastores.ProcessInfo
	currentEntityId := entityId

	for i := 0; i < maxDepth; i++ {
		proc, err := m.GetProcess(currentEntityId)
		if err != nil {
			break
		}
		ancestry = append(ancestry, proc)
		if proc.Ppid == 0 {
			break
		}
		currentEntityId = proc.Ppid
	}

	return ancestry, nil
}

// Mock ContainerStore

type mockContainerStore struct {
	containers map[string]*datastores.ContainerInfo
}

func (m *mockContainerStore) Name() string {
	return "mock_container_store"
}

func (m *mockContainerStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockContainerStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockContainerStore) GetContainer(id string) (*datastores.ContainerInfo, error) {
	container, ok := m.containers[id]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return container, nil
}

func (m *mockContainerStore) GetContainerByName(name string) (*datastores.ContainerInfo, error) {
	for _, container := range m.containers {
		if container.Name == name {
			return container, nil
		}
	}
	return nil, datastores.ErrNotFound
}

// Mock SystemStore

type mockSystemStore struct {
	info *datastores.SystemInfo
}

func (m *mockSystemStore) Name() string {
	return "mock_system_store"
}

func (m *mockSystemStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockSystemStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockSystemStore) GetSystemInfo() *datastores.SystemInfo {
	return m.info
}

// Mock KernelSymbolStore

type mockKernelSymbolStore struct {
	symbols map[uint64][]*datastores.SymbolInfo
	names   map[string]uint64
}

func (m *mockKernelSymbolStore) Name() string {
	return "mock_kernel_symbol_store"
}

func (m *mockKernelSymbolStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockKernelSymbolStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockKernelSymbolStore) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	syms, ok := m.symbols[addr]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return syms, nil
}

func (m *mockKernelSymbolStore) GetSymbolAddress(name string) (uint64, error) {
	addr, ok := m.names[name]
	if !ok {
		return 0, datastores.ErrNotFound
	}
	return addr, nil
}

func (m *mockKernelSymbolStore) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	result := make(map[uint64][]*datastores.SymbolInfo)
	for _, addr := range addrs {
		if syms, ok := m.symbols[addr]; ok {
			result[addr] = syms
		}
	}
	return result, nil
}

// Mock DNSStore

type mockDNSStore struct {
	responses map[string]*datastores.DNSResponse
}

func (m *mockDNSStore) Name() string {
	return "mock_dns_store"
}

func (m *mockDNSStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockDNSStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockDNSStore) GetDNSResponse(query string) (*datastores.DNSResponse, error) {
	resp, ok := m.responses[query]
	if !ok {
		return nil, datastores.ErrNotFound
	}
	return resp, nil
}

// Mock SyscallStore

type mockSyscallStore struct {
	idToName map[int32]string
	nameToID map[string]int32
}

func (m *mockSyscallStore) Name() string {
	return "mock_syscall_store"
}

func (m *mockSyscallStore) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{Status: datastores.HealthHealthy}
}

func (m *mockSyscallStore) GetMetrics() *datastores.DataStoreMetrics {
	return &datastores.DataStoreMetrics{}
}

func (m *mockSyscallStore) GetSyscallName(id int32) (string, error) {
	name, ok := m.idToName[id]
	if !ok {
		return "", datastores.ErrNotFound
	}
	return name, nil
}

func (m *mockSyscallStore) GetSyscallID(name string) (int32, error) {
	id, ok := m.nameToID[name]
	if !ok {
		return 0, datastores.ErrNotFound
	}
	return id, nil
}

// Tests

func TestProcessGetFunction(t *testing.T) {
	registry := &mockRegistry{
		processStore: &mockProcessStore{
			processes: map[uint32]*datastores.ProcessInfo{
				12345: {
					UniqueId:  12345,
					Pid:       1000,
					Ppid:      1,
					Name:      "test_proc",
					Exe:       "/usr/bin/test",
					StartTime: time.Unix(1234567890, 0),
					UID:       1000,
					GID:       1000,
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	// Test successful retrieval
	prog, err := CompileExpression(env, `process.get(12345u).name`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "test_proc", result)

	// Test not found returns null
	prog, err = CompileExpression(env, `process.get(99999u) == null`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestProcessGetAncestryFunction(t *testing.T) {
	registry := &mockRegistry{
		processStore: &mockProcessStore{
			processes: map[uint32]*datastores.ProcessInfo{
				1:   {UniqueId: 1, Pid: 1, Ppid: 0, Name: "init"},
				100: {UniqueId: 100, Pid: 100, Ppid: 1, Name: "parent"},
				200: {UniqueId: 200, Pid: 200, Ppid: 100, Name: "child"},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	// Test ancestry chain
	prog, err := CompileExpression(env, `process.getAncestry(200u, 5).size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result)

	// Test checking if any ancestor is init
	prog, err = CompileExpression(env, `process.getAncestry(200u, 5).exists(p, p.name == "init")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestProcessGetChildrenFunction(t *testing.T) {
	registry := &mockRegistry{
		processStore: &mockProcessStore{
			processes: map[uint32]*datastores.ProcessInfo{
				100: {UniqueId: 100, Pid: 100, Ppid: 1, Name: "parent"},
				200: {UniqueId: 200, Pid: 200, Ppid: 100, Name: "child1"},
				300: {UniqueId: 300, Pid: 300, Ppid: 100, Name: "child2"},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `process.getChildren(100u).size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result)
}

func TestContainerGetFunction(t *testing.T) {
	registry := &mockRegistry{
		containerStore: &mockContainerStore{
			containers: map[string]*datastores.ContainerInfo{
				"abc123": {
					ID:          "abc123",
					Name:        "test_container",
					Image:       "ubuntu:latest",
					ImageDigest: "sha256:abcd1234",
					Runtime:     "docker",
					StartTime:   time.Unix(1234567890, 0),
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `container.get("abc123").image`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "ubuntu:latest", result)

	// Test not found
	prog, _ = CompileExpression(env, `container.get("nonexistent") == null`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestContainerGetByNameFunction(t *testing.T) {
	registry := &mockRegistry{
		containerStore: &mockContainerStore{
			containers: map[string]*datastores.ContainerInfo{
				"abc123": {
					ID:    "abc123",
					Name:  "my_container",
					Image: "nginx:latest",
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `container.getByName("my_container").id`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "abc123", result)
}

func TestSystemInfoFunction(t *testing.T) {
	registry := &mockRegistry{
		systemStore: &mockSystemStore{
			info: &datastores.SystemInfo{
				Architecture:  "x86_64",
				KernelRelease: "5.15.0",
				Hostname:      "testhost",
				OSName:        "Ubuntu",
				OSVersion:     "22.04",
				OSPrettyName:  "Ubuntu 22.04 LTS",
				TraceeVersion: "0.20.0",
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `system.info().architecture`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "x86_64", result)

	prog, _ = CompileExpression(env, `system.info().kernel_release.startsWith("5.")`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestKernelResolveSymbolFunction(t *testing.T) {
	registry := &mockRegistry{
		kernelSymbolStore: &mockKernelSymbolStore{
			symbols: map[uint64][]*datastores.SymbolInfo{
				0xffffffffc0001000: {
					{Name: "test_function", Address: 0xffffffffc0001000, Module: "vmlinux"},
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `kernel.resolveSymbol(18446744072635813888u).size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result)
}

func TestKernelGetSymbolAddressFunction(t *testing.T) {
	registry := &mockRegistry{
		kernelSymbolStore: &mockKernelSymbolStore{
			names: map[string]uint64{
				"sys_execve": 0xffffffff81234000,
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `kernel.getSymbolAddress("sys_execve") > 0u`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)

	// Test not found returns 0
	prog, _ = CompileExpression(env, `kernel.getSymbolAddress("nonexistent") == 0u`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestDNSGetResponseFunction(t *testing.T) {
	registry := &mockRegistry{
		dnsStore: &mockDNSStore{
			responses: map[string]*datastores.DNSResponse{
				"example.com": {
					Query: "example.com",
					IPs:   []string{"93.184.216.34"},
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `dns.getResponse("example.com").ips.size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result)

	// Test not found
	prog, _ = CompileExpression(env, `dns.getResponse("nonexistent.com") == null`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestSyscallGetNameFunction(t *testing.T) {
	registry := &mockRegistry{
		syscallStore: &mockSyscallStore{
			idToName: map[int32]string{
				0:  "read",
				1:  "write",
				59: "execve",
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `syscall.getName(59)`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "execve", result)

	// Test not found returns empty string
	prog, _ = CompileExpression(env, `syscall.getName(9999) == ""`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestSyscallGetIdFunction(t *testing.T) {
	registry := &mockRegistry{
		syscallStore: &mockSyscallStore{
			nameToID: map[string]int32{
				"read":   0,
				"write":  1,
				"execve": 59,
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `syscall.getId("execve")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(59), result)

	// Test not found returns -1
	prog, _ = CompileExpression(env, `syscall.getId("nonexistent") == -1`)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestDatastoresNilSafe(t *testing.T) {
	// Test that functions work gracefully when datastores is nil
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// When datastores is nil, datastore functions should not exist
	_, err = CompileExpression(env, `process.get(1234)`)
	assert.Error(t, err) // Should fail to compile since function doesn't exist
}

func TestDatastoreErrorHandling(t *testing.T) {
	// Test ErrNotFound returns null
	registry := &mockRegistry{
		processStore: &mockProcessStore{
			processes: map[uint32]*datastores.ProcessInfo{},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `process.get(99999u) == null`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

func TestDatastoreComplexConditions(t *testing.T) {
	registry := &mockRegistry{
		processStore: &mockProcessStore{
			processes: map[uint32]*datastores.ProcessInfo{
				1:   {UniqueId: 1, Pid: 1, Name: "init", Exe: "/sbin/init"},
				100: {UniqueId: 100, Pid: 100, Ppid: 1, Name: "bash", Exe: "/bin/bash"},
				200: {UniqueId: 200, Pid: 200, Ppid: 100, Name: "nc", Exe: "/usr/bin/nc"},
			},
		},
		containerStore: &mockContainerStore{
			containers: map[string]*datastores.ContainerInfo{
				"abc123": {
					ID:    "abc123",
					Name:  "suspicious",
					Image: "malicious:latest",
				},
			},
		},
	}

	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	// Complex condition: check if process ancestry contains bash AND container image is malicious
	condition := `process.getAncestry(200u, 5).exists(p, p.name == "bash") && 
	              container.get("abc123").image.contains("malicious")`
	prog, err := CompileCondition(env, condition)
	require.NoError(t, err)
	result, err := EvaluateCondition(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, result)
}
