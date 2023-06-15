package events

import (
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
)

type Capabilities struct {
	caps  map[capabilities.RingType]map[cap.Value]struct{}
	mutex *sync.RWMutex
}

// NewCapabilities creates a new capabilities dependency.
func NewCapabilities(givenCaps map[capabilities.RingType][]cap.Value) *Capabilities {
	capsMap := make(map[capabilities.RingType]map[cap.Value]struct{})

	for ringType, caps := range givenCaps {
		capsMap[ringType] = make(map[cap.Value]struct{})
		for _, cp := range caps {
			capsMap[ringType][cp] = struct{}{}
		}
	}

	return &Capabilities{
		caps:  capsMap,
		mutex: &sync.RWMutex{},
	}
}

// GetCaps returns a copy of the capabilities of the given ring type (thread-safe).
func (c *Capabilities) GetCaps(ringType capabilities.RingType) []cap.Value {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if _, ok := c.caps[ringType]; !ok {
		return []cap.Value{}
	}

	caps := []cap.Value{}

	for k := range c.caps[ringType] {
		caps = append(caps, k)
	}

	return caps
}

// AddRingType adds a ring type to the caps dependency (thread-safe).
func (c *Capabilities) AddRingType(ringType capabilities.RingType) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.addRingType(ringType)
}

// addRingType adds a ring type to the caps dependency (no locking).
func (c *Capabilities) addRingType(ringType capabilities.RingType) {
	if _, ok := c.caps[ringType]; !ok {
		c.caps[ringType] = make(map[cap.Value]struct{})
	}
}

// RemoveRingType removes a ring type from the caps dependency (thread-safe).
func (c *Capabilities) RemoveRingType(ringType capabilities.RingType) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.caps, ringType)
}

// AddCap adds a capability of the given ring type to the caps dependency (thread-safe).
func (c *Capabilities) AddCap(ringType capabilities.RingType, capValue cap.Value) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.addRingType(ringType)
	c.caps[ringType][capValue] = struct{}{}
}

// AddCaps adds multiple caps of the given ring type to the caps dependency (thread-safe).
func (c *Capabilities) AddCaps(ringType capabilities.RingType, caps []cap.Value) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.addRingType(ringType)
	for _, cp := range caps {
		c.caps[ringType][cp] = struct{}{}
	}
}

// RemoveCap removes a capability of the given ring type from the caps dependency (thread-safe).
func (c *Capabilities) RemoveCap(ringType capabilities.RingType, givenCap cap.Value) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.caps[ringType]; !ok {
		return
	}

	c.removeCaps(ringType, []cap.Value{givenCap})
}

// RemoveCaps removes multiple caps of the given ring type from the caps dependency (thread-safe).
func (c *Capabilities) RemoveCaps(ringType capabilities.RingType, givenCaps []cap.Value) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.caps[ringType]; !ok {
		return
	}

	c.removeCaps(ringType, givenCaps)
}

// removeCaps removes multiple caps of the given ring type from the caps dependency (no locking).
func (c *Capabilities) removeCaps(ringType capabilities.RingType, givenCaps []cap.Value) {
	if _, ok := c.caps[ringType]; !ok {
		return
	}

	for _, cp := range givenCaps {
		delete(c.caps[ringType], cp)
	}

	if len(c.caps[ringType]) == 0 {
		delete(c.caps, ringType)
	}
}
