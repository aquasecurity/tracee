package events

import (
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

var createAnEvent = func() *Event {
	return NewEvent(
		12345,               // id
		12345,               // id32Bit
		"test",              // name
		"test",              // docPath
		false,               // internal
		false,               // syscall
		[]string{"default"}, // sets
		nil,                 // deps
		[]trace.ArgMeta{},   // params
	)
}

var createDependencies = func() *Dependencies {
	return NewDependencies(nil, nil, nil, nil, nil)
}

// IDS

// TestEventGetIDAndID32Bit_MultipleThreads tests that GetID and GetID32Bit are thread safe.
func TestEventGetIDAndID32Bit_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				id := event.GetID()
				id32Bit := event.GetID32Bit()
				assert.Equal(t, ID(12345), id)
				assert.Equal(t, ID(12345), id32Bit)
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

// TestEventSetAndGetID32Bit_MultipleThreads tests that SetID32Bit and GetID32Bit are thread safe.
func TestEventSetAndGetID32Bit_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				event.SetID32Bit(ID(i))
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetID32Bit()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.Condition(t, func() bool {
		return event.GetID32Bit() < 10
	})
}

// Name and DocPath

// TestEventSetAndGetNameAndDocPath_MultipleThreads tests that SetName and SetDocPath are thread safe.
func TestEventSetAndGetNameAndDocPath_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				event.SetName(fmt.Sprintf("%d", i))
				event.SetDocPath(fmt.Sprintf("%d", i))
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetName()
				event.GetDocPath()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.Condition(t, func() bool {
		n, _ := strconv.Atoi(event.GetName())
		d, _ := strconv.Atoi(event.GetDocPath())
		return n < 10 && d < 10 // only testing races here, not values
	})
}

// Internal and Syscall

// TestEventSetAndGetInternalAndSyscall_MultipleThreads tests that SetInternal, SetNotInternal,
// SetSyscall and SetNotSyscall are thread safe.
func TestEventSetAndGetInternalAndSyscall_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.IsInternal()
				event.SetInternal()
				event.IsSyscall()
				event.SetNotSyscall()
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.IsInternal()
				event.SetNotInternal()
				event.IsSyscall()
				event.SetSyscall()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.True(t, true, true) // only testing races here, not values
}

// Dependencies

// TestEventSetAndGetDependencies_MultipleThreads tests that SetDependencies and GetDependencies are
// thread safe.
func TestEventSetDependencies_MultipleThreads(t *testing.T) {
	event := createAnEvent()
	dependency := createDependencies()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.SetDependencies(dependency)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetDependencies()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.Equal(t, event.GetDependencies(), dependency)
}

// TestEventSetAndGetDependencies_MultipleThreads tests that SetDependencies and GetDependencies are
// thread safe when called with different instances of Dependencies.
func TestEventSetAndGetDependencies_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.SetDependencies(createDependencies()) // new instance every time
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetDependencies()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.True(t, true, true) // only testing races (for new pointers) here, not values
}

// Sets

// TestEventSetAndGetSets_MultipleThreads tests that SetSets and GetSets are thread safe.
func TestEventSetAndGetSets_MultipleThreads(t *testing.T) {
	event := createAnEvent()

	sets := []string{"test"}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.SetSets(sets)
				wg.Done()
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetSets()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.Equal(t, event.GetSets(), sets)
}

// TestEventAddSets_MultipleThread tests that AddSets is thread safe.
func TestEventAddSets_MultipleThread(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				event.AddSets([]string{fmt.Sprintf("%d", i)})
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	assert.ElementsMatch(t,
		event.GetSets(),
		[]string{"default", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"},
	)
}

// TestEventRemoveSets_MultipleThread tests that RemoveSets is thread safe.
func TestEventRemoveSets_MultipleThread(t *testing.T) {
	event := createAnEvent()

	event.SetSets([]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"})

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				if i%2 != 0 {
					event.RemoveSet(fmt.Sprintf("%d", i))
				}
				wg.Done()
			}(i)
		}

		wg.Done()
	}()

	wg.Wait()

	assert.ElementsMatch(t,
		event.GetSets(),
		[]string{"0", "2", "4", "6", "8"},
	)
}

// Params

// TestEventSetAndGetParams_MultipleThread tests that SetParams and GetParams are thread safe.
func TestEventSetAndGetParams_MultipleThread(t *testing.T) {
	event := createAnEvent()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				event.SetParams([]trace.ArgMeta{
					{
						Name: fmt.Sprintf("%d", i),
						Type: "char*",
					},
				})
				wg.Done()
			}(i)
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				event.GetParams()
				wg.Done()
			}()
		}

		wg.Done()
	}()

	wg.Wait()

	assert.Condition(t, func() bool {
		v, _ := strconv.Atoi(event.GetParams()[0].Name)
		return v < 10
	})
}
