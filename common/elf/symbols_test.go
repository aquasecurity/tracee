package elf

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_findWantedSymbolNames(t *testing.T) {
	tests := []struct {
		name              string
		strtab            []byte
		wantedSymbols     []WantedSymbol
		expectedOffsets   []uint32 // offsets that should be in result
		unexpectedOffsets []uint32 // offsets that should NOT be in result
		expectedCount     int
	}{
		{
			name: "exact matches only",
			strtab: []byte{
				0,                                    // offset 0: empty string
				's', 'y', 'm', 'b', 'o', 'l', '1', 0, // offset 1: "symbol1"
				's', 'y', 'm', 'b', 'o', 'l', '2', 0, // offset 9: "symbol2"
				's', 'y', 'm', 'b', 'o', 'l', '3', 0, // offset 17: "symbol3"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("symbol1"),
				PlainSymbolName("symbol2"),
			},
			expectedOffsets:   []uint32{1, 9},
			unexpectedOffsets: []uint32{17},
			expectedCount:     2,
		},
		{
			name: "tail string optimization",
			strtab: []byte{
				0,                                                                                 // offset 0: empty string
				'm', 'y', '_', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', '_', 'c', 'a', 'l', 'l', 0, // offset 1: "my_function_call", contains "call" at offset 13
				'p', 'r', 'i', 'n', 't', 'f', 0, // offset 18: "printf"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("call"),
				PlainSymbolName("printf"),
			},
			expectedOffsets: []uint32{13, 18}, // "call" as tail string at 13, "printf" at 18
			expectedCount:   2,
		},
		{
			name: "exact match preferred over tail string - tail string first",
			strtab: []byte{
				0,                                                                                 // offset 0: empty string
				'm', 'y', '_', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', '_', 'c', 'a', 'l', 'l', 0, // offset 1: "my_function_call"
				'c', 'a', 'l', 'l', 0, // offset 18: "call" (exact match)
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("call"),
			},
			expectedOffsets:   []uint32{18}, // only exact match at 18
			unexpectedOffsets: []uint32{13}, // not the tail string at 13
			expectedCount:     1,
		},
		{
			name: "exact match preferred over tail string - exact match first",
			strtab: []byte{
				0,                     // offset 0: empty string
				'c', 'a', 'l', 'l', 0, // offset 1: "call" (exact match)
				'm', 'y', '_', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', '_', 'c', 'a', 'l', 'l', 0, // offset 6: "my_function_call"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("my_function_call"),
			},
			expectedOffsets:   []uint32{6},  // only exact match at 6
			unexpectedOffsets: []uint32{18}, // not the tail string at 18
			expectedCount:     1,
		},
		{
			name: "multiple tail strings",
			strtab: []byte{
				0,                               // offset 0: empty string
				'b', 'i', 'g', 'd', 'o', 'g', 0, // offset 1: "bigdog", contains "dog" at offset 4
				'h', 'o', 't', 'd', 'o', 'g', 0, // offset 8: "hotdog", contains "dog" at offset 11
				'c', 'a', 't', 0, // offset 15: "cat"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("dog"),
				PlainSymbolName("cat"),
			},
			expectedOffsets: []uint32{4, 11, 15}, // "dog" at 4 and 11, "cat" at 15
			expectedCount:   3,
		},
		{
			name: "no matches",
			strtab: []byte{
				0,                                    // offset 0: empty string
				's', 'y', 'm', 'b', 'o', 'l', '1', 0, // offset 1: "symbol1"
				's', 'y', 'm', 'b', 'o', 'l', '2', 0, // offset 9: "symbol2"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("not_found"),
				PlainSymbolName("also_not_found"),
			},
			expectedOffsets: []uint32{},
			expectedCount:   0,
		},
		{
			name:   "empty string table",
			strtab: []byte{0}, // Just the initial null byte
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("symbol1"),
			},
			expectedOffsets: []uint32{},
			expectedCount:   0,
		},
		{
			name: "tail string suffix",
			strtab: []byte{
				0,                                              // offset 0: empty string
				'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z', 0, // offset 1-9: "foobarbaz", length 9, tail "baz" at offset 7
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("baz"),
			},
			expectedOffsets: []uint32{7}, // "baz" at offset 7 (1 + 9 - 3)
			expectedCount:   1,
		},
		{
			name: "symbol appears in multiple places - exact and tail",
			strtab: []byte{
				0,                // offset 0: empty string
				'f', 'o', 'o', 0, // offset 1: "foo" (exact)
				'b', 'a', 'r', '_', 'f', 'o', 'o', 0, // offset 5: "bar_foo" (tail is "foo" at offset 9)
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("foo"),
			},
			expectedOffsets:   []uint32{1}, // only exact match at offset 1
			unexpectedOffsets: []uint32{9}, // tail match at 9 is ignored because exact match exists
			expectedCount:     1,
		},
		{
			name: "multiple suffixes in different strings",
			strtab: []byte{
				0,                                                   // offset 0: empty string
				'p', 'r', 'e', 'f', 'i', 'x', '_', 'a', 'b', 'c', 0, // offset 1-10: "prefix_abc", length 10, tail "abc" at offset 8
				'x', '_', 'a', 'b', 'c', 0, // offset 12-16: "x_abc", length 5, tail "abc" at offset 14
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("abc"),
			},
			expectedOffsets: []uint32{8, 14}, // "abc" at offset 8 and 14
			expectedCount:   2,
		},
		{
			name: "wanted symbol is substring of another wanted symbol",
			strtab: []byte{
				0,                                                                                 // offset 0: empty string
				'm', 'y', '_', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', '_', 'c', 'a', 'l', 'l', 0, // offset 1: "my_function_call"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("my_function_call"),
				PlainSymbolName("call"),
			},
			expectedOffsets: []uint32{1, 13}, // "my_function_call" at 1, "call" at 13
			expectedCount:   2,
		},
		{
			name: "single character symbols as tail strings",
			strtab: []byte{
				0,           // offset 0: empty string
				'x', 'a', 0, // offset 1: "xa", tail is "a"
				'z', 'b', 0, // offset 4: "zb", tail is "b"
				'p', 'q', 'a', 0, // offset 7: "pqa", tail is "a"
				'm', 'n', 'b', 0, // offset 11: "mnb", tail is "b"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("a"),
				PlainSymbolName("b"),
			},
			expectedOffsets: []uint32{2, 5, 9, 13}, // "a" at 2 and 9, "b" at 5 and 13 (all as tails)
			expectedCount:   4,
		},
		{
			name: "exact match with same tail strings in different words",
			strtab: []byte{
				0,                                    // offset 0: empty string
				'r', 'u', 'n', 'n', 'i', 'n', 'g', 0, // offset 1: "running", tail "ing" at offset 5
				's', 'i', 'n', 'g', 'i', 'n', 'g', 0, // offset 9: "singing", tail "ing" at offset 13
				'i', 'n', 'g', 0, // offset 17: "ing" (exact)
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("ing"),
			},
			expectedOffsets:   []uint32{17}, // only exact match, not tail strings at 5 and 13
			unexpectedOffsets: []uint32{5, 13},
			expectedCount:     1,
		},
		{
			name: "substring in middle should not match - only suffixes",
			strtab: []byte{
				0,                                              // offset 0: empty string
				'f', 'o', 'o', 'b', 'a', 'r', 'b', 'a', 'z', 0, // offset 1: "foobarbaz"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("bar"), // "bar" is in middle, NOT a suffix
			},
			expectedOffsets:   []uint32{}, // should NOT find "bar" (it's not a suffix)
			unexpectedOffsets: []uint32{2},
			expectedCount:     0,
		},
		{
			name: "consecutive null terminators - empty strings in middle",
			// NOTE: This is a robustness test. In practice, real ELF linkers never create
			// empty string entries (consecutive nulls) in string tables. They would just
			// reference offset 0 for empty strings. This tests defensive handling of
			// malformed or manually crafted string tables.
			strtab: []byte{
				0,                // offset 0: empty string
				'f', 'o', 'o', 0, // offset 1: "foo"
				0,                // offset 5: empty string (unrealistic)
				'b', 'a', 'r', 0, // offset 6: "bar"
				0, 0, // offset 10-11: two empty strings (unrealistic)
				'b', 'a', 'z', 0, // offset 12: "baz"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("foo"),
				PlainSymbolName("bar"),
				PlainSymbolName("baz"),
			},
			expectedOffsets: []uint32{1, 6, 12}, // skip empty strings at 5, 10, 11
			expectedCount:   3,
		},
		{
			name: "wanted symbol only exists as suffix of another string",
			strtab: []byte{
				0,                                                        // offset 0: empty string
				'm', 'y', '_', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', 0, // offset 1-11: "my_function"
			},
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("function"), // suffix starting at offset 4
				PlainSymbolName("tion"),     // suffix starting at offset 8
			},
			expectedOffsets: []uint32{4, 8}, // "function" at 4, "tion" at 8
			expectedCount:   2,
		},
		{
			name: "large string table with chunk boundary",
			strtab: func() []byte {
				// Create a string table larger than chunk size (4096 * 128 = 512KB)
				// to test madvise chunk processing
				chunkSize := 4096 * 128
				buf := make([]byte, 0, chunkSize+1000)
				buf = append(buf, 0) // initial null

				// Fill with dummy strings until near chunk boundary
				for len(buf) < chunkSize-50 {
					buf = append(buf, 'd', 'u', 'm', 'm', 'y', 0)
				}

				// Add target string near chunk boundary
				target := []byte{'t', 'a', 'r', 'g', 'e', 't', '_', 's', 'y', 'm', 'b', 'o', 'l', 0}
				buf = append(buf, target...)

				// Add more strings after chunk boundary
				for len(buf) < chunkSize+500 {
					buf = append(buf, 'm', 'o', 'r', 'e', 0)
				}

				// Add a tail string that crosses chunk
				buf = append(buf, 'p', 'r', 'e', 'f', 'i', 'x', '_', 's', 'y', 'm', 'b', 'o', 'l', 0)

				return buf
			}(),
			wantedSymbols: []WantedSymbol{
				PlainSymbolName("target_symbol"), // should be found as exact match
				PlainSymbolName("symbol"),        // should be found as suffix in both strings
			},
			expectedCount: 3, // target_symbol (exact) + symbol as suffix in target_symbol + symbol as suffix in prefix_symbol
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := findWantedSymbolNames(tt.strtab, tt.wantedSymbols)
			require.NoError(t, err)

			for _, offset := range tt.expectedOffsets {
				assert.Contains(t, result, offset, "expected offset %d not found", offset)
			}

			for _, offset := range tt.unexpectedOffsets {
				assert.NotContains(t, result, offset, "unexpected offset %d found", offset)
			}

			assert.Len(t, result, tt.expectedCount, "unexpected number of matches")
		})
	}
}
