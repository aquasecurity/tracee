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

func (m *mockExtension) Init(t *Tracee) error {
	m.initCalled = true
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

func (m *mockExtension) Close() error {
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
		extensions := GetRegisteredExtensions()
		assert.Nil(t, extensions)
	})

	t.Run("register single extension", func(t *testing.T) {
		// Clear registry
		extensionRegistry = nil

		ext := newMockExtension("test1")
		RegisterExtension(ext)

		extensions := GetRegisteredExtensions()
		require.Len(t, extensions, 1)
		assert.Equal(t, ext, extensions[0])
	})

	t.Run("register multiple extensions", func(t *testing.T) {
		// Clear registry
		extensionRegistry = nil

		ext1 := newMockExtension("test1")
		ext2 := newMockExtension("test2")

		RegisterExtension(ext1)
		RegisterExtension(ext2)

		extensions := GetRegisteredExtensions()
		require.Len(t, extensions, 2)
		assert.Equal(t, ext1, extensions[0])
		assert.Equal(t, ext2, extensions[1])
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

		// Test Init method
		err := ext.Init(tracee)
		assert.NoError(t, err)
		assert.True(t, ext.initCalled)
		assert.False(t, ext.regEventsCalled)
		assert.False(t, ext.runCalled)
		assert.False(t, ext.closeCalled)

		// Test RegisterInitEvents method
		err = ext.RegisterInitEvents(tracee, eventChan)
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
		err = ext.Close()
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

		// Test Init method for all extensions
		for _, ext := range tracee.extensions {
			err := ext.Init(tracee)
			assert.NoError(t, err)
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
			err := ext.Close()
			assert.NoError(t, err)
		}

		// Verify final state - all methods called for both extensions
		mockExts := []*mockExtension{ext1, ext2, ext3}
		for i, mockExt := range mockExts {
			assert.True(t, mockExt.initCalled, "extension %d Init should be called", i+1)
			assert.True(t, mockExt.regEventsCalled, "extension %d RegisterInitEvents should be called", i+1)
			assert.True(t, mockExt.runCalled, "extension %d Run should be called", i+1)
			assert.True(t, mockExt.closeCalled, "extension %d Close should be called", i+1)
		}
	})
}
