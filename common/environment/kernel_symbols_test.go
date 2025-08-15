package environment

import (
	"reflect"
	"strings"
	"testing"
)

type symbolInfo struct {
	name    string
	address uint64
	owner   string
}

func symbolToSymbolInfo(symbol *KernelSymbol) *symbolInfo {
	if symbol == nil {
		return nil
	}
	return &symbolInfo{
		name:    symbol.Name,
		address: symbol.Address,
		owner:   symbol.Owner,
	}
}

// TestNewKernelSymbolTable tests the NewKernelSymbolTable function.
func TestNewKernelSymbolTable(t *testing.T) {
	kst, err := NewKernelSymbolTable(true, false)
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	if kst == nil {
		t.Fatalf("NewKernelSymbolTable() returned nil")
	}

	// Check if symbols is initialized
	if kst.symbols == nil {
		t.Errorf("KernelSymbolTable is not initialized correctly")
	}
}

func getTheOnlySymbol(t *testing.T, kst *KernelSymbolTable) *KernelSymbol {
	i := 0
	var foundSymbol *KernelSymbol
	kst.ForEachSymbol(func(symbol *KernelSymbol) {
		i++
		foundSymbol = symbol
	})
	if i > 1 {
		t.Errorf("multiple symbols found")
	}
	return foundSymbol
}

// TestUpdate tests the kallsyms parsing logic.
func TestUpdate(t *testing.T) {
	testCases := []struct {
		buf      string
		expected *symbolInfo
	}{
		{"ffffffff00000001	t	my_symbol	[my_owner]", &symbolInfo{name: "my_symbol", address: 0xffffffff00000001, owner: "my_owner"}},
		{"ffffffff00000002	T	another_symbol", &symbolInfo{name: "another_symbol", address: 0xffffffff00000002, owner: "system"}},
		{"invalid_address	T	invalid_symbol", nil},
		{"ffffffff00000003	T", nil},
	}

	for _, tc := range testCases {
		kst, err := NewKernelSymbolTableFromReader(strings.NewReader(tc.buf), false, false)
		if err != nil {
			t.Fatalf("NewKernelSymbolTableFromReader() failed: %v", err)
		}
		symbol := getTheOnlySymbol(t, kst)
		result := symbolToSymbolInfo(symbol)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("update(%v) = %v; want %v", tc.buf, result, tc.expected)
		}
	}
}

// TestGetSymbolByName tests the GetSymbolByName function.
func TestGetSymbolByName(t *testing.T) {
	buf := "ffffffff00000001	t	test_symbol	test_owner"
	kst, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), false, false)
	if err != nil {
		t.Fatalf("NewKernelSymbolTableFromReader() failed: %v", err)
	}

	symbols, err := kst.GetSymbolByName("test_symbol")
	if err != nil {
		t.Fatalf("GetSymbolByName() failed: %v", err)
	}

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expected := &symbolInfo{name: "test_symbol", address: 0xffffffff00000001, owner: "test_owner"}
	result := symbolToSymbolInfo(symbols[0])
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GetSymbolByName() = %v; want %v", result, expected)
	}
}

// TestGetSymbolByOwnerAndName tests the GetSymbolByOwnerAndName function.
func TestGetSymbolByOwnerAndName(t *testing.T) {
	buf := `ffffffff00000001	t	test_symbol	test_owner1
ffffffff00000002	t	test_symbol	test_owner2`
	kst, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), false, false)
	if err != nil {
		t.Fatalf("NewKernelSymbolTableFromReader() failed: %v", err)
	}

	symbols, err := kst.GetSymbolByOwnerAndName("test_owner1", "test_symbol")
	if err != nil {
		t.Fatalf("GetSymbolByName() failed: %v", err)
	}

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expected := &symbolInfo{name: "test_symbol", address: 0xffffffff00000001, owner: "test_owner1"}
	result := symbolToSymbolInfo(symbols[0])
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GetSymbolByOwnerAndName() = %v; want %v", result, expected)
	}
}

// TestGetSymbolByAddr tests the GetSymbolByAddr function.
func TestGetSymbolByAddr(t *testing.T) {
	buf := "ffffffff00001234	t	test_symbol	test_owner"
	kst, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), false, false)
	if err != nil {
		t.Fatalf("NewKernelSymbolTableFromReader() failed: %v", err)
	}

	symbols, err := kst.GetSymbolByAddr(0xffffffff00001234)
	if err != nil {
		t.Fatalf("GetSymbolByAddr() failed: %v", err)
	}

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expected := &symbolInfo{name: "test_symbol", address: 0xffffffff00001234, owner: "test_owner"}
	result := symbolToSymbolInfo(symbols[0])
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GetSymbolByAddr() = %v; want %v", result, expected)
	}
}

// TestGetPotentiallyHiddenSymbolByAddr tests the GetPotentiallyHiddenSymbolByAddr function.
func TestGetPotentiallyHiddenSymbolByAddr(t *testing.T) {
	buf := "ffffffff00000001	t	test_symbol	test_owner"
	kst, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), false, false)
	if err != nil {
		t.Fatalf("NewKernelSymbolTableFromReader() failed: %v", err)
	}

	symbols := kst.GetPotentiallyHiddenSymbolByAddr(0xffffffff00000002)

	if len(symbols) != 1 {
		t.Errorf("Expected 1 symbol, got %d", len(symbols))
	}

	expected := &symbolInfo{name: "", address: 0xffffffff00000002, owner: "hidden"}
	result := symbolToSymbolInfo(symbols[0])
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("GetSymbolByAddr() = %v; want %v", result, expected)
	}
}
