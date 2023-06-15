package events

//
// Dependencies: Capabilities
//

func (d *Dependencies) SetCapabilities(capabilities *Capabilities) {
	d.capabilities.Store(capabilities)
}

func (d *Dependencies) GetCapabilities() *Capabilities {
	return d.capabilities.Load()
}
