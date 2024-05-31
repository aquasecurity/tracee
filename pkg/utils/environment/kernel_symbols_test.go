package environment

import (
	"reflect"
	"testing"
)

// TestParseLine tests the parseKallsymsLine function.
func TestParseKallsymsLine(t *testing.T) {
	testCases := []struct {
		line     []string
		expected *KernelSymbol
	}{
		{[]string{"00000000", "t", "my_symbol", "[my_owner]"}, &KernelSymbol{Name: "my_symbol", Type: "t", Address: 0, Owner: "my_owner"}},
		{[]string{"00000001", "T", "another_symbol"}, &KernelSymbol{Name: "another_symbol", Type: "T", Address: 1, Owner: "system"}},
		{[]string{"invalid_address", "T", "invalid_symbol"}, nil},
		{[]string{"00000002", "T"}, nil},
	}

	for _, tc := range testCases {
		result := parseKallsymsLine(tc.line)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("parseKallsymsLine(%v) = %v; want %v", tc.line, result, tc.expected)
		}
	}
}

// TestNewKernelSymbolTable tests the NewKernelSymbolTable function.
func TestNewKernelSymbolTable(t *testing.T) {
	kst, err := NewKernelSymbolTable()
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	if kst == nil {
		t.Fatalf("NewKernelSymbolTable() returned nil")
	}

	// Check if the onlyRequired flag is set correctly
	if kst.onlyRequired {
		t.Errorf("onlyRequired flag should be false by default")
	}

	// Check if maps are initialized
	if kst.symbols == nil || kst.addrs == nil || kst.symByName == nil || kst.symByAddr == nil {
		t.Errorf("KernelSymbolTable maps are not initialized correctly")
	}
}

// TestGetSymbolByName tests the GetSymbolByName function.
func TestGetSymbolByName(t *testing.T) {
	kst, err := NewKernelSymbolTable()
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	kst.symbols["test_symbol"] = []*KernelSymbol{
		{Name: "test_symbol", Type: "t", Address: 0, Owner: "test_owner"},
	}

	symbols, err := kst.GetSymbolByName("test_symbol")
	if err != nil {
		t.Fatalf("GetSymbolByName() failed: %v", err)
	}

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expectedSymbol := KernelSymbol{Name: "test_symbol", Type: "t", Address: 0, Owner: "test_owner"}
	if !reflect.DeepEqual(symbols[0], expectedSymbol) {
		t.Errorf("GetSymbolByName() = %v; want %v", symbols[0], expectedSymbol)
	}
}

// TestGetSymbolByAddr tests the GetSymbolByAddr function.
func TestGetSymbolByAddr(t *testing.T) {
	kst, err := NewKernelSymbolTable()
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	kst.addrs[0x1234] = []*KernelSymbol{
		{Name: "test_symbol", Type: "t", Address: 0x1234, Owner: "test_owner"},
	}

	symbols, err := kst.GetSymbolByAddr(0x1234)
	if err != nil {
		t.Fatalf("GetSymbolByAddr() failed: %v", err)
	}

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expectedSymbol := KernelSymbol{Name: "test_symbol", Type: "t", Address: 0x1234, Owner: "test_owner"}
	if !reflect.DeepEqual(symbols[0], expectedSymbol) {
		t.Errorf("GetSymbolByAddr() = %v; want %v", symbols[0], expectedSymbol)
	}
}

// TestRefresh tests the Refresh function.
func TestRefresh(t *testing.T) {
	// Creating a mock KernelSymbolTable with required symbols to test Refresh
	kst, err := NewKernelSymbolTable(WithRequiredSymbols([]string{"_stext", "_etext"}))
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	// Simulate the presence of these symbols
	kst.symbols["_stext"] = []*KernelSymbol{{Name: "_stext", Type: "T", Address: 0x1000, Owner: "system"}}
	kst.symbols["_etext"] = []*KernelSymbol{{Name: "_etext", Type: "T", Address: 0x2000, Owner: "system"}}

	// Call Refresh to update the symbol table
	if err := kst.Refresh(); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Check if symbols were added correctly
	symbolsToTest := []string{"_stext", "_etext"}
	for _, symbol := range symbolsToTest {
		if syms, err := kst.GetSymbolByName(symbol); err != nil || len(syms) == 0 {
			t.Errorf("Expected to find symbol %s, but it was not found", symbol)
		}
	}
}

// TestTextSegmentContains tests the TextSegmentContains function.
func TestTextSegmentContains(t *testing.T) {
	// Creating a mock KernelSymbolTable with text segment addresses
	kst, err := NewKernelSymbolTable()
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	kst.symByName[nameAndOwner{"_stext", "system"}] = []*KernelSymbol{{Name: "_stext", Type: "T", Address: 0x1000, Owner: "system"}}
	kst.symByName[nameAndOwner{"_etext", "system"}] = []*KernelSymbol{{Name: "_etext", Type: "T", Address: 0x2000, Owner: "system"}}

	tests := []struct {
		addr     uint64
		expected bool
	}{
		{0x1000, true},
		{0x1500, true},
		{0x2000, false},
		{0x0999, false},
	}

	for _, tt := range tests {
		result, err := kst.TextSegmentContains(tt.addr)
		if err != nil {
			t.Errorf("TextSegmentContains(%v) failed: %v", tt.addr, err)
		}
		if result != tt.expected {
			t.Errorf("TextSegmentContains(%v) = %v; want %v", tt.addr, result, tt.expected)
		}
	}
}

// Helper function to test required symbols or addresses.
func TestValidateOrAddRequired(t *testing.T) {
	kst, err := NewKernelSymbolTable(WithRequiredSymbols([]string{"test_symbol"}))
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	kst.requiredSyms["test_symbol"] = struct{}{}

	if err := kst.validateOrAddRequiredSym("test_symbol"); err != nil {
		t.Errorf("validateOrAddRequiredSym() failed: %v", err)
	}

	if err := kst.validateOrAddRequiredAddr(0x1234); err != nil {
		t.Errorf("validateOrAddRequiredAddr() failed: %v", err)
	}
}
