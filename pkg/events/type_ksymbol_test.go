package events

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// NOTE: KSymbol type describes a single ksymbol, concurrency tests under dep_ksymbols_test.go

// TestKSymbol_NewKSymbol tests that NewKSymbol returns a new KSymbol with the correct symbol name.
func TestKSymbol_NewKSymbol(t *testing.T) {
	kSymbol := NewKSymbol("foo", true)
	require.Equal(t, "foo", kSymbol.GetSymbol())
	require.True(t, kSymbol.IsRequired())
}

// TestKSymbol_SetRequired tests that SetRequired sets the required flag to true.
func TestKSymbol_SetRequired(t *testing.T) {
	kSymbol := NewKSymbol("foo", false)
	kSymbol.SetRequired()
	require.True(t, kSymbol.IsRequired())
}

// TestKSymbol_SetNotRequired tests that SetNotRequired sets the required flag to false.
func TestKSymbol_SetNotRequired(t *testing.T) {
	kSymbol := NewKSymbol("foo", true)
	kSymbol.SetNotRequired()
	require.False(t, kSymbol.IsRequired())
}

// TestKSymbol_GetSymbol tests that GetSymbol returns the symbol name of the KSymbol.
func TestKSymbol_GetSymbol(t *testing.T) {
	kSymbol := NewKSymbol("foo", true)
	require.Equal(t, "foo", kSymbol.GetSymbol())
	kSymbolNoSymbol := NewKSymbol("", true)
	require.Empty(t, kSymbolNoSymbol.GetSymbol())
}
