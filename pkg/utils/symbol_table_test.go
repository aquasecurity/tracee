package utils

import (
	"reflect"
	"testing"
)

type testSymbol struct {
	name string
	addr uint64
	size uint64
}

func (s testSymbol) Name() string {
	return s.name
}

func (s testSymbol) Address() uint64 {
	return s.addr
}

func (s testSymbol) Contains(address uint64) bool {
	return s.addr <= address && s.addr+s.size > address
}

func (s testSymbol) Clone() testSymbol {
	return testSymbol{
		name: s.name,
		addr: s.addr,
		size: s.size,
	}
}

// TestNewSymbolTable tests the NewSymbolTable function.
func TestNewSymbolTable(t *testing.T) {
	st := NewSymbolTable[testSymbol](true)
	if st == nil {
		t.Fatalf("NewSymbolTable() returned nil")
	}

	if !st.lazyNameLookup {
		t.Errorf("lazyNameLookup was not set to true")
	}

	if st.sortedSymbols == nil || st.symbolsByName == nil {
		t.Errorf("data structures are nil")
	}
}

// TestAddSymbols tests the AddSymbols function
func TestAddSymbols(t *testing.T) {
	testCases := []struct {
		symbols       []*testSymbol
		expectedOrder []int
	}{
		{[]*testSymbol{
			{name: "symbol1", addr: 1, size: 1},
			{name: "symbol2", addr: 1, size: 1},
		}, []int{0, 1}},
		{[]*testSymbol{
			{name: "symbol1", addr: 2, size: 1},
			{name: "symbol2", addr: 1, size: 1},
		}, []int{0, 1}},
		{[]*testSymbol{
			{name: "symbol1", addr: 1, size: 1},
			{name: "symbol2", addr: 2, size: 1},
		}, []int{1, 0}},
	}

	for _, tc := range testCases {
		st := NewSymbolTable[testSymbol](false)
		st.AddSymbols(tc.symbols)

		if len(st.sortedSymbols) != len(tc.symbols) {
			t.Errorf("len(st.sortedSymbol) = %d, want %d", len(st.sortedSymbols), len(tc.symbols))
			continue
		}

		for i := range st.sortedSymbols {
			if !reflect.DeepEqual(*st.sortedSymbols[i], *tc.symbols[tc.expectedOrder[i]]) {
				t.Errorf("AddSymbols(%v) = symbol %d: %v; want %v", tc.symbols, i, st.sortedSymbols[i], tc.symbols[tc.expectedOrder[i]])
			}
		}
	}
}

// TestLookupByName tests the LookupByName function
func TestLookupByName(t *testing.T) {
	testCases := []struct {
		symbols           []*testSymbol
		lookupName        string
		expectLookupError bool
		expected          []testSymbol
	}{
		{
			[]*testSymbol{{name: "symbol1", addr: 1, size: 1}},
			"symbol1",
			false,
			[]testSymbol{{name: "symbol1", addr: 1, size: 1}},
		},
		{
			[]*testSymbol{},
			"symbol2",
			true,
			[]testSymbol{},
		},
		{
			[]*testSymbol{{name: "symbol3", addr: 1, size: 1}},
			"symbol4",
			true,
			[]testSymbol{},
		},
		{
			[]*testSymbol{{name: "symbol5", addr: 1, size: 1}, {name: "symbol6", addr: 2, size: 2}},
			"symbol6",
			false,
			[]testSymbol{{name: "symbol6", addr: 2, size: 2}},
		},
		{
			[]*testSymbol{{name: "symbol7", addr: 1, size: 1}, {name: "symbol7", addr: 2, size: 2}},
			"symbol7",
			false,
			[]testSymbol{{name: "symbol7", addr: 1, size: 1}, {name: "symbol7", addr: 2, size: 2}},
		},
	}

	for _, tc := range testCases {
		st := NewSymbolTable[testSymbol](false)
		st.AddSymbols(tc.symbols)
		result, err := st.LookupByName(tc.lookupName)
		if !tc.expectLookupError && err != nil {
			t.Errorf("LookupByName(%s) failed: %v", tc.lookupName, err)
			continue
		} else if tc.expectLookupError {
			if err == nil {
				t.Errorf("LookupByName(%s) expected to fail but didn't", tc.lookupName)
			}
			continue
		}
		if !reflect.DeepEqual(copySliceOfPointersToSliceOfStructs(result), tc.expected) {
			t.Errorf("LookupByName(%s) = %v, expected %v", tc.lookupName, copySliceOfPointersToSliceOfStructs(result), tc.expected)
		}
	}
}

// TestLazyNameLookup tests the lazy name lookup functionality
func TestLazyNameLookup(t *testing.T) {
	testCases := []struct {
		symbols          []*testSymbol
		lazyNameLookup   bool
		lookups          []string
		expectedMappings []int
	}{
		{
			[]*testSymbol{{name: "symbol", addr: 1, size: 1}},
			false,
			[]string{},
			[]int{0},
		},
		{
			[]*testSymbol{{name: "symbol", addr: 1, size: 1}},
			true,
			[]string{},
			[]int{},
		},
		{
			[]*testSymbol{{name: "symbol1", addr: 1, size: 1}, {name: "symbol2", addr: 2, size: 1}},
			true,
			[]string{"symbol1", "symbol2"},
			[]int{0, 1},
		},
		{
			[]*testSymbol{{name: "symbol1", addr: 1, size: 1}, {name: "symbol2", addr: 2, size: 1}},
			true,
			[]string{"symbol2"},
			[]int{1},
		},
	}

testLoop:
	for _, tc := range testCases {
		st := NewSymbolTable[testSymbol](tc.lazyNameLookup)
		st.AddSymbols(tc.symbols)
		if tc.lazyNameLookup {
			if len(st.symbolsByName) != 0 {
				t.Errorf("len(st.symbolsByName) = %d, expected 0", len(st.symbolsByName))
				continue
			}
		} else {
			if len(st.symbolsByName) != len(tc.symbols) {
				t.Errorf("len(st.symbolsByName) = %d, expected %d", len(st.symbolsByName), len(tc.symbols))
				continue
			}
		}
		for _, lookupName := range tc.lookups {
			_, err := st.LookupByName(lookupName)
			if err != nil {
				t.Errorf("LookupByName(%s) failed: %v", lookupName, err)
				continue testLoop
			}
		}
		for i := range tc.expectedMappings {
			if !reflect.DeepEqual(*(st.symbolsByName[tc.symbols[tc.expectedMappings[i]].name][0]), *tc.symbols[tc.expectedMappings[i]]) {
				t.Errorf("st.symbolsByName[\"%s\"] = %v, expected %v", tc.symbols[tc.expectedMappings[i]].name, *(st.symbolsByName[tc.symbols[tc.expectedMappings[i]].name][0]), *tc.symbols[tc.expectedMappings[i]])
				continue
			}
		}
	}
}

// TestLookupByAddressExact tests the LookupByAddressExact function
func TestLookupByAddressExact(t *testing.T) {
	testCases := []struct {
		symbols           []*testSymbol
		lookupAddr        uint64
		expectLookupError bool
		expected          []testSymbol
	}{
		{
			[]*testSymbol{{name: "symbol1", addr: 1, size: 1}},
			1,
			false,
			[]testSymbol{{name: "symbol1", addr: 1, size: 1}},
		},
		{
			[]*testSymbol{},
			2,
			true,
			[]testSymbol{},
		},
		{
			[]*testSymbol{{name: "symbol3", addr: 3, size: 1}},
			4,
			true,
			[]testSymbol{},
		},
		{
			[]*testSymbol{{name: "symbol5", addr: 5, size: 1}, {name: "symbol6", addr: 6, size: 2}},
			6,
			false,
			[]testSymbol{{name: "symbol6", addr: 6, size: 2}},
		},
		{
			[]*testSymbol{{name: "symbol7", addr: 7, size: 1}, {name: "symbol8", addr: 7, size: 2}},
			7,
			false,
			[]testSymbol{{name: "symbol7", addr: 7, size: 1}, {name: "symbol8", addr: 7, size: 2}},
		},
	}

	for _, tc := range testCases {
		st := NewSymbolTable[testSymbol](false)
		st.AddSymbols(tc.symbols)
		result, err := st.LookupByAddressExact(tc.lookupAddr)
		if !tc.expectLookupError && err != nil {
			t.Errorf("LookupByAddressExact(%d) failed: %v", tc.lookupAddr, err)
			continue
		} else if tc.expectLookupError && err == nil {
			t.Errorf("LookupByAddressExact(%d) expected to fail but didn't", tc.lookupAddr)
			continue
		}
		if !reflect.DeepEqual(copySliceOfPointersToSliceOfStructs(result), tc.expected) {
			t.Errorf("LookupByAddressExact(%d) = %v, expected %v", tc.lookupAddr, copySliceOfPointersToSliceOfStructs(result), tc.expected)
		}
	}
}

// TestLookupByAddressContains tests the LookupByAddressContains function
func TestLookupByAddressContains(t *testing.T) {
	testCases := []struct {
		symbols    []*testSymbol
		lookupAddr uint64
		expected   *testSymbol
	}{
		{
			[]*testSymbol{},
			1,
			nil,
		},
		{
			[]*testSymbol{{name: "symbol1", addr: 2, size: 2}},
			2,
			&testSymbol{name: "symbol1", addr: 2, size: 2},
		},
		{
			[]*testSymbol{{name: "symbol2", addr: 3, size: 2}},
			4,
			&testSymbol{name: "symbol2", addr: 3, size: 2},
		},
		{
			[]*testSymbol{{name: "symbol3", addr: 4, size: 2}},
			6,
			nil,
		},
		{
			[]*testSymbol{{name: "symbol4", addr: 10, size: 2}},
			8,
			nil,
		},
		{
			[]*testSymbol{{name: "symbol5", addr: 11, size: 2}},
			14,
			nil,
		},
		{
			[]*testSymbol{{name: "symbol6", addr: 15, size: 5}, {name: "symbol7", addr: 17, size: 3}},
			18,
			&testSymbol{name: "symbol7", addr: 17, size: 3},
		},
		{ // this is a special case assumed to be impossible in practice, see the docstring of LookupByAddressContains()
			[]*testSymbol{{name: "symbol8", addr: 20, size: 5}, {name: "symbol9", addr: 21, size: 2}},
			23,
			nil,
		},
	}

	for _, tc := range testCases {
		st := NewSymbolTable[testSymbol](false)
		st.AddSymbols(tc.symbols)
		result, err := st.LookupByAddressContains(tc.lookupAddr)
		if tc.expected != nil && err != nil {
			t.Errorf("LookupByAddressContains(%d) failed: %v", tc.lookupAddr, err)
			continue
		}
		if tc.expected == nil {
			if err == nil {
				t.Errorf("LookupByAddressContains(%d) expected to fail, but returned %v", tc.lookupAddr, *result)
			}
			continue
		}
		if !reflect.DeepEqual(*result, *tc.expected) {
			t.Errorf("LookupByAddressContains(%d) = %v, expected %v", tc.lookupAddr, *result, *tc.expected)
		}
	}
}

// copySliceOfPointersToSliceOfStructs converts a slice of pointers to a slice of structs.
func copySliceOfPointersToSliceOfStructs(s []*testSymbol) []testSymbol {
	ret := make([]testSymbol, len(s))
	for i, v := range s {
		ret[i] = *v
	}
	return ret
}
