package ebpf

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/types/trace"
)

// mockExtension is a mock implementation of the Extension interface for testing
type mockExtension struct {
	name        string
	initCalled  bool
	initError   error
	initPhases  []InitPhase // Track which phases were called
	runCalled   bool
	runError    error
	closeCalled bool
	closeError  error
}

func newMockExtension(name string) *mockExtension {
	return &mockExtension{
		name: name,
	}
}

func (m *mockExtension) Init(ctx context.Context, t *Tracee, phase InitPhase) error {
	m.initCalled = true
	m.initPhases = append(m.initPhases, phase)
	return m.initError
}

func (m *mockExtension) Run(ctx context.Context, t *Tracee) error {
	m.runCalled = true
	return m.runError
}

func (m *mockExtension) Close(t *Tracee) error {
	m.closeCalled = true
	return m.closeError
}

func TestExtensionRegistry(t *testing.T) {
	// Save original registry and restore at the end
	extensionRegistryMu.Lock()
	originalRegistry := make([]Extension, len(extensionRegistry))
	copy(originalRegistry, extensionRegistry)
	extensionRegistryMu.Unlock()

	defer func() {
		extensionRegistryMu.Lock()
		extensionRegistry = originalRegistry
		extensionRegistryMu.Unlock()
	}()

	// Clear registry for testing
	extensionRegistryMu.Lock()
	extensionRegistry = nil
	extensionRegistryMu.Unlock()

	t.Run("empty registry", func(t *testing.T) {
		extensions := NewExtensions()
		registeredExtensions := extensions.GetRegisteredExtensions()
		assert.Nil(t, registeredExtensions)
	})

	t.Run("register single extension", func(t *testing.T) {
		// Clear registry
		extensionRegistryMu.Lock()
		extensionRegistry = nil
		extensionRegistryMu.Unlock()

		ext := newMockExtension("test1")
		RegisterExtension(ext)

		extensions := NewExtensions()
		registeredExtensions := extensions.GetRegisteredExtensions()
		require.Len(t, registeredExtensions, 1)
		assert.Equal(t, ext, registeredExtensions[0])
	})

	t.Run("register multiple extensions", func(t *testing.T) {
		// Clear registry
		extensionRegistryMu.Lock()
		extensionRegistry = nil
		extensionRegistryMu.Unlock()

		ext1 := newMockExtension("test1")
		ext2 := newMockExtension("test2")

		RegisterExtension(ext1)
		RegisterExtension(ext2)

		extensions := NewExtensions()
		registeredExtensions := extensions.GetRegisteredExtensions()
		require.Len(t, registeredExtensions, 2)
		assert.Equal(t, ext1, registeredExtensions[0])
		assert.Equal(t, ext2, registeredExtensions[1])
	})
}

func TestExtensionInterface(t *testing.T) {
	t.Run("exercise all interface methods", func(t *testing.T) {
		ext := newMockExtension("interface-test")
		tracee := &Tracee{}
		ctx := context.Background()
		eventChan := make(chan *trace.Event, 1)
		defer close(eventChan)

		// Test Init method with multiple phases
		phases := []InitPhase{InitPhaseContainers, InitPhaseBPFProbes, InitPhaseKernelSymbols, InitPhaseComplete}
		for _, phase := range phases {
			err := ext.Init(ctx, tracee, phase)
			assert.NoError(t, err)
		}
		assert.True(t, ext.initCalled)
		assert.Equal(t, phases, ext.initPhases, "All phases should be recorded")
		assert.False(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test Run method
		err := ext.Run(ctx, tracee)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.True(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test Close method
		err = ext.Close(tracee)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.True(t, ext.runCalled)
		assert.True(t, ext.closeCalled)
	})

	t.Run("exercise three extensions together", func(t *testing.T) {
		ext1 := newMockExtension("extension-1")
		ext2 := newMockExtension("extension-2")
		ext3 := newMockExtension("extension-3")

		// Clear registry and register test extensions
		extensionRegistryMu.Lock()
		originalRegistry := make([]Extension, len(extensionRegistry))
		copy(originalRegistry, extensionRegistry)
		extensionRegistry = []Extension{ext1, ext2, ext3}
		extensionRegistryMu.Unlock()

		defer func() {
			extensionRegistryMu.Lock()
			extensionRegistry = originalRegistry
			extensionRegistryMu.Unlock()
		}()

		extensions := NewExtensions()
		tracee := &Tracee{extensions: extensions}
		ctx := context.Background()
		eventChans := []chan *trace.Event{
			make(chan *trace.Event, 1),
			make(chan *trace.Event, 1),
			make(chan *trace.Event, 1),
		}
		defer func() {
			for _, ch := range eventChans {
				close(ch)
			}
		}()

		// Test Init method for all extensions with multiple phases
		testPhases := []InitPhase{InitPhaseContainers, InitPhaseBPFProbes, InitPhaseKernelSymbols, InitPhaseBPFPrograms, InitPhaseComplete}
		for _, phase := range testPhases {
			err := extensions.InitExtensionsForPhase(ctx, tracee, phase)
			assert.NoError(t, err)
		}

		// Test Run method for all extensions
		err := extensions.RunExtensions(ctx, tracee)
		assert.NoError(t, err)

		// Test Close method for all extensions
		err = extensions.CloseExtensions(tracee)
		assert.NoError(t, err)

		// Verify final state - all methods called for all extensions
		mockExts := []*mockExtension{ext1, ext2, ext3}
		for i, mockExt := range mockExts {
			assert.True(t, mockExt.initCalled, "extension %d Init should be called", i+1)
			assert.Equal(t, testPhases, mockExt.initPhases, "extension %d should have all phases recorded", i+1)
			assert.True(t, mockExt.runCalled, "extension %d Run should be called", i+1)
			assert.True(t, mockExt.closeCalled, "extension %d Close should be called", i+1)
		}
	})
}

func TestExtensionInitPhases(t *testing.T) {
	t.Run("test extension all init phases", func(t *testing.T) {
		ext := newMockExtension("phase-test")
		tracee := &Tracee{}
		ctx := context.Background()
		// Test each phase individually
		allPhases := []InitPhase{
			InitPhaseStart,
			InitPhaseCGroups,
			InitPhaseContainers,
			InitPhaseBPFProbes,
			InitPhaseKernelSymbols,
			InitPhaseBPFPrograms,
			InitPhaseComplete,
		}

		for _, phase := range allPhases {
			err := ext.Init(ctx, tracee, phase)
			assert.NoError(t, err)
		}

		assert.True(t, ext.initCalled)
		assert.Equal(t, allPhases, ext.initPhases)
		assert.Len(t, ext.initPhases, 7, "Should have recorded all 7 phases")
	})

	t.Run("test extension helper function with multiple extensions and init phase", func(t *testing.T) {
		ext1 := newMockExtension("helper-test-1")
		ext2 := newMockExtension("helper-test-2")
		ext3 := newMockExtension("helper-test-3")

		// Clear registry and register test extensions
		originalRegistry := extensionRegistry
		extensionRegistry = []Extension{ext1, ext2, ext3}

		defer func() {
			extensionRegistry = originalRegistry
		}()

		extensions := NewExtensions()
		tracee := &Tracee{extensions: extensions}
		ctx := context.Background()
		err := extensions.InitExtensionsForPhase(ctx, tracee, InitPhaseBPFProbes)
		assert.NoError(t, err)

		// Verify all extensions were initialized with the correct phase
		mockExts := []*mockExtension{ext1, ext2, ext3}
		for i, mockExt := range mockExts {
			assert.True(t, mockExt.initCalled, "extension %d should be initialized", i+1)
			assert.Contains(t, mockExt.initPhases, InitPhaseBPFProbes, "extension %d should have correct phase", i+1)
		}
	})

	t.Run("test extension helper function with extension error and init phase", func(t *testing.T) {
		ext := newMockExtension("error-test")
		ext.initError = assert.AnError

		// Clear registry and register test extension
		originalRegistry := extensionRegistry
		extensionRegistry = []Extension{ext}

		defer func() {
			extensionRegistry = originalRegistry
		}()

		extensions := NewExtensions()
		tracee := &Tracee{extensions: extensions}
		ctx := context.Background()
		err := extensions.InitExtensionsForPhase(ctx, tracee, InitPhaseKernelSymbols)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize extension 0 during phase InitPhaseKernelSymbols")
		assert.True(t, ext.initCalled)
	})
}
