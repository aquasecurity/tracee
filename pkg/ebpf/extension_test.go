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
	name            string
	initCalled      bool
	initError       error
	initPhases      []InitPhase // Track which phases were called
	regEventsCalled bool
	regEventsError  error
	runCalled       bool
	runError        error
	closeCalled     bool
	closeError      error
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

func (m *mockExtension) RegisterInitEvents(t *Tracee, out chan *trace.Event) error {
	m.regEventsCalled = true
	return m.regEventsError
}

func (m *mockExtension) Run(ctx context.Context, t *Tracee) error {
	m.runCalled = true
	return m.runError
}

func (m *mockExtension) Close(t *Tracee) error {
	m.closeCalled = true
	return m.closeError
}

// mockEventCallback for testing event callbacks
type mockEventCallback struct {
	called bool
	event  interface{}
}

func (m *mockEventCallback) callback(event interface{}) {
	m.called = true
	m.event = event
}

// mockProbe for testing probe handling
type mockProbe struct {
	name string
	data string
}

func TestExtensionRegistry(t *testing.T) {
	t.Parallel()

	// Save original registry and restore at the end
	originalRegistry := extensionRegistry
	defer func() {
		extensionRegistry = originalRegistry
	}()

	// Clear registry for testing
	extensionRegistry = nil

	t.Run("empty registry", func(t *testing.T) {
		tracee := &Tracee{}
		tracee.loadExtensions()
		assert.Nil(t, tracee.extensions)
	})

	t.Run("register single extension", func(t *testing.T) {
		// Clear registry
		extensionRegistry = nil

		ext := newMockExtension("test1")
		RegisterExtension(ext)

		tracee := &Tracee{}
		tracee.loadExtensions()
		require.Len(t, tracee.extensions, 1)
		assert.Equal(t, ext, tracee.extensions[0])
	})

	t.Run("register multiple extensions", func(t *testing.T) {
		// Clear registry
		extensionRegistry = nil

		ext1 := newMockExtension("test1")
		ext2 := newMockExtension("test2")

		RegisterExtension(ext1)
		RegisterExtension(ext2)

		tracee := &Tracee{}
		tracee.loadExtensions()
		require.Len(t, tracee.extensions, 2)
		assert.Equal(t, ext1, tracee.extensions[0])
		assert.Equal(t, ext2, tracee.extensions[1])
	})
}

func TestExtensionInterface(t *testing.T) {
	t.Parallel()

	t.Run("exercise all interface methods", func(t *testing.T) {
		ext := newMockExtension("interface-test")
		tracee := &Tracee{}
		ctx := context.Background()
		eventChan := make(chan *trace.Event, 1)
		defer close(eventChan)

		// Test Init method with multiple phases
		phases := []InitPhase{INIT_CONTAINERS, INIT_BPF_PROBES, INIT_KERNEL_SYMBOLS, INIT_COMPLETE}
		for _, phase := range phases {
			err := ext.Init(ctx, tracee, phase)
			assert.NoError(t, err)
		}
		assert.True(t, ext.initCalled)
		assert.Equal(t, phases, ext.initPhases, "All phases should be recorded")
		assert.False(t, ext.regEventsCalled)
		assert.False(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test RegisterInitEvents method
		err := ext.RegisterInitEvents(tracee, eventChan)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.True(t, ext.regEventsCalled)
		assert.False(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test Run method
		err = ext.Run(ctx, tracee)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.True(t, ext.regEventsCalled)
		assert.True(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test Close method
		err = ext.Close(tracee)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.True(t, ext.regEventsCalled)
		assert.True(t, ext.runCalled)
		assert.True(t, ext.closeCalled)
	})

	t.Run("exercise three extensions together", func(t *testing.T) {
		ext1 := newMockExtension("extension-1")
		ext2 := newMockExtension("extension-2")
		ext3 := newMockExtension("extension-3")
		tracee := &Tracee{extensions: []Extension{ext1, ext2, ext3}}
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
		testPhases := []InitPhase{INIT_CONTAINERS, INIT_BPF_PROBES, INIT_KERNEL_SYMBOLS, INIT_BPF_PROGRAMS, INIT_COMPLETE}
		for _, phase := range testPhases {
			for _, ext := range tracee.extensions {
				err := ext.Init(ctx, tracee, phase)
				assert.NoError(t, err)
			}
		}

		// Test RegisterInitEvents method for all extensions
		for i, ext := range tracee.extensions {
			err := ext.RegisterInitEvents(tracee, eventChans[i])
			assert.NoError(t, err)
		}

		// Test Run method for all extensions
		for _, ext := range tracee.extensions {
			err := ext.Run(ctx, tracee)
			assert.NoError(t, err)
		}

		// Test Close method for all extensions
		for _, ext := range tracee.extensions {
			err := ext.Close(tracee)
			assert.NoError(t, err)
		}

		// Verify final state - all methods called for all extensions
		mockExts := []*mockExtension{ext1, ext2, ext3}
		for i, mockExt := range mockExts {
			assert.True(t, mockExt.initCalled, "extension %d Init should be called", i+1)
			assert.Equal(t, testPhases, mockExt.initPhases, "extension %d should have all phases recorded", i+1)
			assert.True(t, mockExt.regEventsCalled, "extension %d RegisterInitEvents should be called", i+1)
			assert.True(t, mockExt.runCalled, "extension %d Run should be called", i+1)
			assert.True(t, mockExt.closeCalled, "extension %d Close should be called", i+1)
		}
	})
}

func TestExtensionInitPhases(t *testing.T) {
	t.Parallel()

	t.Run("test extension all init phases", func(t *testing.T) {
		ext := newMockExtension("phase-test")
		tracee := &Tracee{}
		ctx := context.Background()
		// Test each phase individually
		allPhases := []InitPhase{
			INIT_START,
			INIT_CGROUPS,
			INIT_CONTAINERS,
			INIT_BPF_PROBES,
			INIT_KERNEL_SYMBOLS,
			INIT_BPF_PROGRAMS,
			INIT_COMPLETE,
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
		tracee := &Tracee{extensions: []Extension{ext1, ext2, ext3}}
		ctx := context.Background()
		err := tracee.initExtensionsWithPhase(ctx, INIT_BPF_PROBES)
		assert.NoError(t, err)

		// Verify all extensions were initialized with the correct phase
		mockExts := []*mockExtension{ext1, ext2, ext3}
		for i, mockExt := range mockExts {
			assert.True(t, mockExt.initCalled, "extension %d should be initialized", i+1)
			assert.Contains(t, mockExt.initPhases, INIT_BPF_PROBES, "extension %d should have correct phase", i+1)
		}
	})

	t.Run("test extension helper function with extension error and init phase", func(t *testing.T) {
		ext := newMockExtension("error-test")
		ext.initError = assert.AnError
		tracee := &Tracee{extensions: []Extension{ext}}
		ctx := context.Background()
		err := tracee.initExtensionsWithPhase(ctx, INIT_KERNEL_SYMBOLS)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error initializing extension with phase")
		assert.True(t, ext.initCalled)
	})
}
