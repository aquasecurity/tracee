package events

//
// Dependencies: Capabilities
//

// SetCapabilities sets the capabilities to a new given set (thread-safe).
func (d *Dependencies) SetCapabilities(capabilities *Capabilities) {
	d.capabilities.Store(capabilities)
}

// GetCapabilities returns a copy of the instanced capabilities (thread-safe).
func (d *Dependencies) GetCapabilities() *Capabilities {
	return d.capabilities.Load()
}
