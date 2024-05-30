package environment

import (
	"reflect"
	"testing"
)

// TestParseLine tests the parseLine function.
func TestParseLine(t *testing.T) {
	testCases := []struct {
		line     []string
		expected *KernelSymbol
	}{
		{[]string{"00000000", "t", "my_symbol", "[my_owner]"}, &KernelSymbol{Name: "my_symbol", Type: "t", Address: 0, Owner: "my_owner"}},
		// Add more test cases as needed.
	}

	for _, tc := range testCases {
		result := parseLine(tc.line)
		if !reflect.DeepEqual(result, tc.expected) {
			t.Errorf("parseLine(%v) = %v; want %v", tc.line, result, tc.expected)
		}
	}
}

func TestRefresh(t *testing.T) {
	kst, err := NewKernelSymbolTable()
	if err != nil {
		t.Fatalf("NewKernelSymbolTable() failed: %v", err)
	}

	// Test well-known symbols like _stext and _etext.
	symbolsToTest := []string{"_stext", "_etext"}

	for _, symbol := range symbolsToTest {
		if syms, err := kst.GetSymbolByName(symbol); err != nil || len(syms) == 0 {
			t.Errorf("Expected to find symbol %s, but it was not found", symbol)
		}
	}

	// Text the text swegment contains function.
	if _, err := kst.TextSegmentContains(0); err != nil {
		t.Errorf("TextSegmentContains failed: %v", err)
	}
}
