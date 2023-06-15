package events

//
// Dependencies: KSymbols
//

// SetKSymbols sets the kSymbols to a new given set (thread-safe).
func (d *Dependencies) SetKSymbols(kSymbols []*KSymbol) {
	d.kSymbolsLock.Lock()
	defer d.kSymbolsLock.Unlock()

	// delete all previous kSymbols
	for k := range d.kSymbols {
		delete(d.kSymbols, k)
	}

	d.addKSymbols(kSymbols)
}

// GetKSymbols returns a slice copy of instanced kSymbols (thread-safe).
func (d *Dependencies) GetKSymbols() []*KSymbol {
	d.kSymbolsLock.RLock()
	defer d.kSymbolsLock.RUnlock()

	a := []*KSymbol{}
	for _, v := range d.kSymbols {
		a = append(a, v)
	}

	return a
}

// AddKSymbol adds a kSymbol dependency to the event (thread-safe).
func (d *Dependencies) AddKSymbol(kSymbol *KSymbol) {
	d.kSymbolsLock.Lock()
	defer d.kSymbolsLock.Unlock()

	d.kSymbols[kSymbol.GetSymbol()] = kSymbol
}

func (d *Dependencies) AddKSymbols(kSymbols []*KSymbol) {
	d.kSymbolsLock.Lock()
	defer d.kSymbolsLock.Unlock()

	d.addKSymbols(kSymbols)
}

func (d *Dependencies) DelKSymbol(symbol string) {
	d.kSymbolsLock.Lock()
	defer d.kSymbolsLock.Unlock()

	delete(d.kSymbols, symbol)
}

// DelKSymbols removes kSymbols dependencies from the event (thread-safe).
func (d *Dependencies) DelKSymbols(symbols []string) {
	d.kSymbolsLock.Lock()
	defer d.kSymbolsLock.Unlock()

	for _, e := range symbols {
		delete(d.kSymbols, e)
	}
}

// addKSymbols adds kSymbols dependencies to the event (no locking).
func (d *Dependencies) addKSymbols(symbols []*KSymbol) {
	for _, s := range symbols {
		d.kSymbols[s.GetSymbol()] = s
	}
}
