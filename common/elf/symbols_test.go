package elf

import (
	"debug/elf"
	"testing"
)

func TestPlainSymbolName(t *testing.T) {
	name := PlainSymbolName("test_symbol")

	// Test Matches method
	if !name.Matches("test_symbol") {
		t.Error("Expected exact match to return true")
	}

	if name.Matches("other_symbol") {
		t.Error("Expected non-match to return false")
	}

	// Test String method
	if name.String() != "test_symbol" {
		t.Errorf("Expected String() to return %q, got %q", "test_symbol", name.String())
	}
}

func TestNewPlainSymbolName(t *testing.T) {
	symbol := NewPlainSymbolName("my_function")

	if !symbol.Matches("my_function") {
		t.Error("Expected created symbol to match its name")
	}

	if symbol.String() != "my_function" {
		t.Error("Expected String() to return original name")
	}
}

func TestWantedSymbolsFromStrings(t *testing.T) {
	// Test with symbols
	symbols := map[string]struct{}{
		"func1": {},
		"func2": {},
		"func3": {},
	}

	wanted := WantedSymbolsFromStrings(symbols)

	if len(wanted) != 3 {
		t.Errorf("Expected 3 symbols, got %d", len(wanted))
	}

	// Verify all symbols are present
	found := make(map[string]bool)
	for _, w := range wanted {
		found[w.String()] = true
	}

	for name := range symbols {
		if !found[name] {
			t.Errorf("Symbol %q not found in result", name)
		}
	}

	// Test with empty map
	empty := WantedSymbolsFromStrings(nil)
	if empty != nil {
		t.Error("Expected nil for empty input")
	}

	empty = WantedSymbolsFromStrings(map[string]struct{}{})
	if empty != nil {
		t.Error("Expected nil for empty map")
	}
}

func TestElfSymbolIsImported(t *testing.T) {
	// Test imported symbol
	imported := ElfSymbol{
		Info:    byte(elf.STB_GLOBAL) << 4, // STB_GLOBAL in upper 4 bits
		Section: elf.SHN_UNDEF,
	}

	if !imported.IsImported() {
		t.Error("Expected global undefined symbol to be imported")
	}

	// Test local symbol
	local := ElfSymbol{
		Info:    byte(elf.STB_LOCAL) << 4,
		Section: 1, // Some defined section
	}

	if local.IsImported() {
		t.Error("Expected local symbol to not be imported")
	}

	// Test global defined symbol
	defined := ElfSymbol{
		Info:    byte(elf.STB_GLOBAL) << 4,
		Section: 1, // Some defined section
	}

	if defined.IsImported() {
		t.Error("Expected global defined symbol to not be imported")
	}
}

func TestErrSymbolNotFound(t *testing.T) {
	if ErrSymbolNotFound == nil {
		t.Error("ErrSymbolNotFound should not be nil")
	}

	expected := "symbol not found"
	if ErrSymbolNotFound.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, ErrSymbolNotFound.Error())
	}
}
