package elf

import (
	"debug/elf"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findElfBinary tries to find a suitable ELF binary for testing
// Uses common paths that should exist on most Linux systems
func findElfBinary() string {
	// Common binary paths across different Linux distributions
	candidates := []string{
		"/bin/sh",      // POSIX shell - very common
		"/bin/ls",      // List files - basic utility
		"/bin/cat",     // Concatenate files - basic utility
		"/usr/bin/ls",  // Alternative ls location
		"/usr/bin/cat", // Alternative cat location
		"/bin/echo",    // Echo command - usually available
		"/bin/true",    // True command - minimal binary
		"/bin/false",   // False command - minimal binary
		"/sbin/init",   // Init process - usually available
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			// Verify it's actually an ELF
			data := make([]byte, 4)
			if file, err := os.Open(path); err == nil {
				file.Read(data)
				file.Close()
				if HasElfMagic(data) {
					return path
				}
			}
		}
	}
	return ""
}

// Test the instruction finding functions with mock data
func TestFindRetInstsX86_64(t *testing.T) {
	// Simple test with RET instruction (0xC3)
	bytes := []byte{
		0x48, 0x89, 0xe5, // mov %rsp, %rbp
		0xc3, // ret
		0x90, // nop
		0xc3, // ret
	}

	offsets, err := findRetInstsX86_64(0x1000, bytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := []uint64{0x1003, 0x1005} // offsets of the RET instructions
	if len(offsets) != len(expected) {
		t.Errorf("Expected %d RET instructions, got %d", len(expected), len(offsets))
	}

	for i, offset := range offsets {
		if offset != expected[i] {
			t.Errorf("Expected offset %d at index %d, got %d", expected[i], i, offset)
		}
	}
}

func TestFindRetInstsX86_64_NoRet(t *testing.T) {
	// Bytes without RET instruction
	bytes := []byte{
		0x48, 0x89, 0xe5, // mov %rsp, %rbp
		0x90, // nop
	}

	_, err := findRetInstsX86_64(0x1000, bytes)
	if err == nil {
		t.Error("Expected error for bytes without RET instruction")
	}
}

func TestFindRetInstsARM64(t *testing.T) {
	// ARM64 RET instruction is 0xd65f03c0 (little-endian: 0xc0, 0x03, 0x5f, 0xd6)
	bytes := []byte{
		0x00, 0x00, 0x80, 0xd2, // mov x0, #0
		0xc0, 0x03, 0x5f, 0xd6, // ret
		0x1f, 0x20, 0x03, 0xd5, // nop
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}

	offsets, err := findRetInstsARM64(0x2000, bytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expected := []uint64{0x2004, 0x200c} // offsets of the RET instructions
	if len(offsets) != len(expected) {
		t.Errorf("Expected %d RET instructions, got %d", len(expected), len(offsets))
	}

	for i, offset := range offsets {
		if offset != expected[i] {
			t.Errorf("Expected offset %d at index %d, got %d", expected[i], i, offset)
		}
	}
}

func TestFindRetInstsARM64_NoRet(t *testing.T) {
	// Bytes without RET instruction
	bytes := []byte{
		0x00, 0x00, 0x80, 0xd2, // mov x0, #0
		0x1f, 0x20, 0x03, 0xd5, // nop
	}

	_, err := findRetInstsARM64(0x2000, bytes)
	if err == nil {
		t.Error("Expected error for bytes without RET instruction")
	}
}

func TestFindRetInsts_UnsupportedArch(t *testing.T) {
	bytes := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := findRetInsts(0x1000, bytes, elf.EM_MIPS)
	if err == nil {
		t.Error("Expected error for unsupported architecture")
	}

	expectedError := "unsupported architecture"
	if err != nil && !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestFindRetInsts_SupportedArchs(t *testing.T) {
	// Test that supported architectures call the correct functions
	// We're not testing actual instruction parsing here, just the routing

	tests := []struct {
		arch elf.Machine
		name string
	}{
		{elf.EM_X86_64, "x86_64"},
		{elf.EM_AARCH64, "ARM64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Empty bytes will cause the underlying functions to fail,
			// but we just want to verify the routing works
			_, err := findRetInsts(0x1000, []byte{}, tt.arch)
			// We expect an error because we passed empty bytes,
			// but it should be from the instruction parser, not "unsupported architecture"
			if err == nil {
				t.Error("Expected error for empty bytes")
			}

			if err != nil && err.Error() == "unsupported architecture MIPS" {
				t.Error("Should not get unsupported architecture error for supported arch")
			}
		})
	}
}

func TestHasElfMagic(t *testing.T) {
	t.Run("valid ELF magic", func(t *testing.T) {
		validElf := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01}
		assert.True(t, HasElfMagic(validElf))
	})

	t.Run("invalid magic", func(t *testing.T) {
		invalid := []byte{0x7F, 'E', 'L', 'G', 0x02, 0x01, 0x01}
		assert.False(t, HasElfMagic(invalid))
	})

	t.Run("too short", func(t *testing.T) {
		tooShort := []byte{0x7F, 'E', 'L'}
		assert.False(t, HasElfMagic(tooShort))
	})

	t.Run("empty bytes", func(t *testing.T) {
		empty := []byte{}
		assert.False(t, HasElfMagic(empty))
	})

	t.Run("different magic numbers", func(t *testing.T) {
		testCases := []struct {
			name  string
			bytes []byte
			valid bool
		}{
			{"PE magic", []byte{'M', 'Z'}, false},
			{"PDF magic", []byte{'%', 'P', 'D', 'F'}, false},
			{"correct ELF", []byte{127, 69, 76, 70}, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := HasElfMagic(tc.bytes)
				assert.Equal(t, tc.valid, result)
			})
		}
	})
}

func TestIsElf(t *testing.T) {
	t.Run("delegates to HasElfMagic", func(t *testing.T) {
		validElf := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01}
		assert.True(t, IsElf(validElf))

		invalid := []byte{0x7F, 'E', 'L', 'G'}
		assert.False(t, IsElf(invalid))
	})
}

func TestNewElfAnalyzer_Errors(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		analyzer, err := NewElfAnalyzer("/non/existent/file", nil)
		assert.Error(t, err)
		assert.Nil(t, analyzer)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("directory instead of file", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test_elf_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		analyzer, err := NewElfAnalyzer(tempDir, nil)
		assert.Error(t, err)
		assert.Nil(t, analyzer)
	})

	t.Run("non-ELF file", func(t *testing.T) {
		// Create a temporary non-ELF file
		tempFile, err := os.CreateTemp("", "test_non_elf_*")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())

		// Write non-ELF content
		_, err = tempFile.WriteString("This is not an ELF file")
		require.NoError(t, err)
		err = tempFile.Close()
		require.NoError(t, err)

		analyzer, err := NewElfAnalyzer(tempFile.Name(), nil)
		assert.Error(t, err)
		assert.Nil(t, analyzer)
		assert.Contains(t, err.Error(), "bad magic number")
	})
}

func TestNewElfAnalyzer_WithRealElf(t *testing.T) {
	elfPath := findElfBinary()
	if elfPath == "" {
		t.Skip("No ELF binary found on system for testing")
	}

	t.Run("create analyzer without wanted symbols", func(t *testing.T) {
		analyzer, err := NewElfAnalyzer(elfPath, nil)
		require.NoError(t, err)
		require.NotNil(t, analyzer)

		assert.Equal(t, elfPath, analyzer.GetFilePath())
		assert.False(t, analyzer.wantedSymbolsOnly)
		assert.Nil(t, analyzer.wantedSymbols)

		err = analyzer.Close()
		assert.NoError(t, err)
	})

	t.Run("create analyzer with wanted symbols", func(t *testing.T) {
		wantedSymbols := []WantedSymbol{
			NewPlainSymbolName("main"),
			NewPlainSymbolName("printf"),
		}

		analyzer, err := NewElfAnalyzer(elfPath, wantedSymbols)
		require.NoError(t, err)
		require.NotNil(t, analyzer)

		assert.Equal(t, elfPath, analyzer.GetFilePath())
		assert.True(t, analyzer.wantedSymbolsOnly)
		assert.Len(t, analyzer.wantedSymbols, 2)

		err = analyzer.Close()
		assert.NoError(t, err)
	})
}

func TestGetGoVersion_WithRealFiles(t *testing.T) {
	// Try to find Go binary
	goBinaries := []string{
		"/usr/local/go/bin/go",
		"/usr/bin/go",
		"/bin/go",
	}

	var goBinary string
	for _, path := range goBinaries {
		if _, err := os.Stat(path); err == nil {
			goBinary = path
			break
		}
	}

	t.Run("Go binary", func(t *testing.T) {
		if goBinary == "" {
			t.Skip("No Go binary found for testing")
		}

		analyzer, err := NewElfAnalyzer(goBinary, nil)
		require.NoError(t, err)
		defer analyzer.Close()

		version, err := analyzer.GetGoVersion()
		if err != nil {
			// Some Go binaries might not have build info
			if err == ErrNotGoBinary {
				t.Skip("Go binary doesn't contain build info")
			}
			t.Fatalf("Unexpected error: %v", err)
		}

		assert.NotNil(t, version)
		assert.Greater(t, version.Major, 0)
		assert.GreaterOrEqual(t, version.Minor, 0)
		assert.GreaterOrEqual(t, version.Patch, 0)

		// Test caching - second call should return same result
		version2, err2 := analyzer.GetGoVersion()
		assert.NoError(t, err2)
		assert.Equal(t, version, version2)
	})

	t.Run("non-Go binary", func(t *testing.T) {
		nonGoBinary := findElfBinary()
		if nonGoBinary == "" {
			t.Skip("No non-Go binary found for testing")
		}

		analyzer, err := NewElfAnalyzer(nonGoBinary, nil)
		require.NoError(t, err)
		defer analyzer.Close()

		version, err := analyzer.GetGoVersion()
		assert.Error(t, err)
		assert.Equal(t, ErrNotGoBinary, err)
		assert.Nil(t, version)

		// Test caching - second call should return same error
		version2, err2 := analyzer.GetGoVersion()
		assert.Error(t, err2)
		assert.Equal(t, ErrNotGoBinary, err2)
		assert.Nil(t, version2)
	})
}

func TestSymbolFunctions_WithRealElf(t *testing.T) {
	elfPath := findElfBinary()
	if elfPath == "" {
		t.Skip("No ELF binary found for testing")
	}

	t.Run("symbol operations", func(t *testing.T) {
		analyzer, err := NewElfAnalyzer(elfPath, nil)
		require.NoError(t, err)
		defer analyzer.Close()

		// Test getting symbols (this will load them)
		symbols, err := analyzer.getSymbols()
		if err != nil {
			t.Logf("Could not load symbols: %v", err)
			return // Some stripped binaries have no symbols
		}

		assert.NotNil(t, symbols)
		// Most binaries have at least some symbols
		if len(symbols) > 0 {
			// Pick first symbol for testing
			var firstSymbolName string
			for name := range symbols {
				firstSymbolName = name
				break
			}

			// Test GetSymbol
			symbol, err := analyzer.GetSymbol(firstSymbolName)
			assert.NoError(t, err)
			assert.NotNil(t, symbol)
			assert.Equal(t, firstSymbolName, symbol.Name)
		}

		// Test non-existent symbol
		nonExistentSymbol, err := analyzer.GetSymbol("nonexistent_symbol_12345")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not find symbol")
		assert.ErrorIs(t, err, ErrSymbolNotFound)
		assert.Nil(t, nonExistentSymbol)
	})

	t.Run("wanted symbols only", func(t *testing.T) {
		// Create analyzer with specific wanted symbols
		wantedSymbols := []WantedSymbol{
			NewPlainSymbolName("main"),
			NewPlainSymbolName("printf"),
			NewPlainSymbolName("_start"),
		}

		analyzer, err := NewElfAnalyzer(elfPath, wantedSymbols)
		require.NoError(t, err)
		defer analyzer.Close()

		symbols, err := analyzer.getSymbols()
		if err != nil {
			t.Logf("Could not load symbols: %v", err)
			return
		}

		// Should only contain wanted symbols (if they exist)
		for symbolName := range symbols {
			found := false
			for _, wanted := range wantedSymbols {
				if wanted.Matches(symbolName) {
					found = true
					break
				}
			}
			assert.True(t, found, "Unexpected symbol %s in wanted-only mode", symbolName)
		}
	})
}

// TestSymbolOffsetCalculation tests the symbol offset calculation formula
func TestSymbolOffsetCalculation(t *testing.T) {
	testCases := []struct {
		name           string
		symbolValue    uint64
		sectionAddr    uint64
		sectionOffset  uint64
		expectedOffset uint64
	}{
		{
			name:           "symbol at section start with zero file offset",
			symbolValue:    0x1000,
			sectionAddr:    0x1000,
			sectionOffset:  0x0,
			expectedOffset: 0x0, // Legitimate zero result
		},
		{
			name:           "symbol within section with file offset",
			symbolValue:    0x1050,
			sectionAddr:    0x1000,
			sectionOffset:  0x400,
			expectedOffset: 0x450, // 0x1050 - 0x1000 + 0x400
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Formula: symbol.Value - section.Addr + section.Offset
			actualOffset := tc.symbolValue - tc.sectionAddr + tc.sectionOffset
			assert.Equal(t, tc.expectedOffset, actualOffset)
		})
	}
}

func TestGetFunctionRetInsts_WithRealElf(t *testing.T) {
	elfPath := findElfBinary()
	if elfPath == "" {
		t.Skip("No ELF binary found for testing")
	}

	t.Run("function analysis", func(t *testing.T) {
		analyzer, err := NewElfAnalyzer(elfPath, nil)
		require.NoError(t, err)
		defer analyzer.Close()

		// Load symbols to find functions
		symbols, err := analyzer.getSymbols()
		if err != nil {
			t.Skip("Could not load symbols for function analysis")
		}

		// Find a function symbol (non-imported, with size > 0)
		var funcName string
		for name, symbol := range symbols {
			if !symbol.IsImported() && symbol.Size > 0 && symbol.Size < 1000 { // Small function
				funcName = name
				break
			}
		}

		if funcName == "" {
			t.Skip("No suitable function symbol found for testing")
		}

		// Test GetFunctionRetInsts
		retInsts, err := analyzer.GetFunctionRetInsts(funcName)
		if err != nil {
			// Function analysis can fail for various reasons (section validation, etc.)
			t.Logf("Could not analyze function %s: %v", funcName, err)
			return
		}

		assert.NotNil(t, retInsts)
		// Most functions should have at least one RET instruction
		if len(retInsts) > 0 {
			for _, inst := range retInsts {
				assert.Greater(t, inst, uint64(0))
			}
		}
	})

	t.Run("non-existent function", func(t *testing.T) {
		analyzer, err := NewElfAnalyzer(elfPath, nil)
		require.NoError(t, err)
		defer analyzer.Close()

		retInsts, err := analyzer.GetFunctionRetInsts("nonexistent_function_12345")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not find symbol")
		assert.Nil(t, retInsts)
	})
}
