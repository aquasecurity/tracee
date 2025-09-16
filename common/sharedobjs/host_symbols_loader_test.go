package sharedobjs

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type soCacheMock struct {
	get func(ObjID) (*Symbols, bool)
	add func(obj ObjInfo, dynamicSymbols *Symbols)
}

func (s soCacheMock) Get(identification ObjID) (*Symbols, bool) {
	if s.get != nil {
		return s.get(identification)
	}
	return nil, false
}

func (s soCacheMock) Add(obj ObjInfo, dynamicSymbols *Symbols) {
	if s.add != nil {
		s.add(obj, dynamicSymbols)
	}
}

var testLoadedObjectInfo = ObjInfo{
	Id: ObjID{
		Inode:  10,
		Device: 10,
		Ctime:  10,
	},
	Path:    "/tmp/test.so",
	MountNS: 1,
}

var testDynamicSymbols = &Symbols{
	Exported: map[string]bool{"open": true, "close": true},
	Imported: map[string]bool{"syscall": true},
}

func TestHostSharedObjectSymbolsLoader_GetDynamicSymbols(t *testing.T) {
	t.Parallel()

	t.Run("Happy flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				return testDynamicSymbols, true
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetDynamicSymbols(testLoadedObjectInfo)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprint(map[string]bool{"open": true, "close": true, "syscall": true}), fmt.Sprint(syms))
	})

	t.Run("Sad flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetDynamicSymbols(testLoadedObjectInfo)
		assert.Error(t, err)
		assert.Nil(t, syms)
	})
}

func TestHostSharedObjectSymbolsLoader_GetExportedSymbols(t *testing.T) {
	t.Parallel()

	t.Run("Happy flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				return testDynamicSymbols, true
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetExportedSymbols(testLoadedObjectInfo)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprint(map[string]bool{"open": true, "close": true}), fmt.Sprint(syms))
	})

	t.Run("Sad flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetExportedSymbols(testLoadedObjectInfo)
		assert.Error(t, err)
		assert.Nil(t, syms)
	})
}

func TestHostSharedObjectSymbolsLoader_GetImportedSymbols(t *testing.T) {
	t.Parallel()

	t.Run("Happy flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				return testDynamicSymbols, true
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetImportedSymbols(testLoadedObjectInfo)
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprint(map[string]bool{"syscall": true}), fmt.Sprint(syms))
	})

	t.Run("Sad flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.GetImportedSymbols(testLoadedObjectInfo)
		assert.Error(t, err)
		assert.Nil(t, syms)
	})
}

func TestHostSharedObjectSymbolsLoader_loadSOSymbols(t *testing.T) {
	t.Parallel()

	t.Run("Cached SO", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				return testDynamicSymbols, true
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.loadSOSymbols(testLoadedObjectInfo)
		assert.NoError(t, err)
		assert.Equal(t, testDynamicSymbols, syms)
	})

	t.Run("Uncached non existing SO", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*Symbols, error) {
			return nil, errors.New("no SO")
		}
		cachedSymbols := make(map[ObjInfo]*Symbols)
		cache := soCacheMock{
			add: func(obj ObjInfo, dynamicSymbols *Symbols) {
				cachedSymbols[obj] = dynamicSymbols
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: failLoadingFunc,
			soCache:     cache,
		}
		syms, err := soLoader.loadSOSymbols(testLoadedObjectInfo)
		assert.Error(t, err)
		assert.Nil(t, syms)
		require.Len(t, cachedSymbols, 0)
	})

	t.Run("Uncached existing SO", func(t *testing.T) {
		t.Parallel()

		cachedSymbols := make(map[ObjInfo]*Symbols)
		cache := soCacheMock{
			add: func(obj ObjInfo, dynamicSymbols *Symbols) {
				cachedSymbols[obj] = dynamicSymbols
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: func(path string) (*Symbols, error) {
				return testDynamicSymbols, nil
			},
			soCache: cache,
		}
		syms, err := soLoader.loadSOSymbols(testLoadedObjectInfo)
		assert.NoError(t, err)
		assert.Equal(t, testDynamicSymbols, syms)
		require.Len(t, cachedSymbols, 1)
		require.Contains(t, cachedSymbols, testLoadedObjectInfo)
		assert.Equal(t, testDynamicSymbols, cachedSymbols[testLoadedObjectInfo])
	})
}

func TestParseDynamicSymbols(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name          string
		Input         []elf.Symbol
		ExpecteResult Symbols
	}{
		{
			Name:          "No symbols",
			Input:         []elf.Symbol{},
			ExpecteResult: NewSOSymbols(),
		},
		{
			Name:  "Full details import symbols",
			Input: []elf.Symbol{{Name: "__ctype_toupper_loc", Info: 18, Section: elf.SHN_UNDEF + 12, Version: "GLIBC_2.3", Library: "libc.so.6"}},
			ExpecteResult: Symbols{
				Exported: make(map[string]bool),
				Imported: map[string]bool{
					"__ctype_toupper_loc": true,
				},
			},
		},
		{
			Name:  "Missing details import symbol",
			Input: []elf.Symbol{{Name: "cap_to_text", Info: 18, Section: elf.SHN_UNDEF}},
			ExpecteResult: Symbols{
				Exported: make(map[string]bool),
				Imported: map[string]bool{
					"cap_to_text": true,
				},
			},
		},
		{
			Name:  "Export import symbol",
			Input: []elf.Symbol{{Name: "_obstack_memory_used", Info: 18, Section: elf.SHN_UNDEF + 12, Value: 55424, Size: 38}},
			ExpecteResult: Symbols{
				Exported: map[string]bool{
					"_obstack_memory_used": true,
				},
				Imported: make(map[string]bool),
			},
		},
		{
			Name: "Mixed symbols",
			Input: []elf.Symbol{
				{Name: "__ctype_toupper_loc", Info: 18, Section: elf.SHN_UNDEF + 12, Version: "GLIBC_2.3", Library: "libc.so.6"},
				{Name: "cap_to_text", Info: 18, Section: elf.SHN_UNDEF},
				{Name: "_obstack_memory_used", Info: 18, Section: elf.SHN_UNDEF + 12, Value: 55424, Size: 38},
			},
			ExpecteResult: Symbols{
				Exported: map[string]bool{
					"_obstack_memory_used": true,
				},
				Imported: map[string]bool{
					"__ctype_toupper_loc": true,
					"cap_to_text":         true,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			dynamicSymbols := parseSymbols([]elf.Symbol{}, testCase.Input)
			assert.Equal(t, fmt.Sprint(testCase.ExpecteResult.Imported), fmt.Sprint(dynamicSymbols.Imported))
			assert.Equal(t, fmt.Sprint(testCase.ExpecteResult.Exported), fmt.Sprint(dynamicSymbols.Exported))
		})
	}
}

func TestInitHostSymbolsLoader(t *testing.T) {
	tests := []struct {
		name      string
		cacheSize int
	}{
		{"default cache size", 100},
		{"small cache", 1},
		{"large cache", 1000},
		{"zero cache", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := InitHostSymbolsLoader(tt.cacheSize)

			assert.NotNil(t, loader)
			assert.NotNil(t, loader.soCache)
			assert.NotNil(t, loader.loadingFunc)
		})
	}
}

func TestHostSharedObjectSymbolsLoader_GetLocalSymbols(t *testing.T) {
	t.Parallel()

	testSymbols := &Symbols{
		Exported: map[string]bool{"open": true},
		Imported: map[string]bool{"syscall": true},
		Local:    map[string]bool{"local_func": true, "local_var": true},
	}

	t.Run("Happy flow", func(t *testing.T) {
		t.Parallel()

		cacheMock := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				if identification == testLoadedObjectInfo.Id {
					return testSymbols, true
				}
				return nil, false
			},
		}

		loader := &HostSymbolsLoader{
			soCache: cacheMock,
		}

		result, err := loader.GetLocalSymbols(testLoadedObjectInfo)

		require.NoError(t, err)
		assert.Equal(t, testSymbols.Local, result)
	})

	t.Run("Sad flow", func(t *testing.T) {
		t.Parallel()

		cacheMock := soCacheMock{
			get: func(identification ObjID) (*Symbols, bool) {
				return nil, false
			},
		}

		loader := &HostSymbolsLoader{
			soCache: cacheMock,
			loadingFunc: func(path string) (*Symbols, error) {
				return nil, errors.New("failed to load symbols")
			},
		}

		result, err := loader.GetLocalSymbols(testLoadedObjectInfo)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestDynamicSymbolsLRUCache_Get(t *testing.T) {
	loader := InitHostSymbolsLoader(10)
	cache, ok := loader.soCache.(*dynamicSymbolsLRUCache)
	require.True(t, ok)

	testSymbols := &Symbols{
		Exported: map[string]bool{"test": true},
		Imported: map[string]bool{"import": true},
		Local:    map[string]bool{"local": true},
	}

	// Test cache miss
	result, found := cache.Get(testLoadedObjectInfo.Id)
	assert.False(t, found)
	assert.Nil(t, result)

	// Add to cache
	cache.Add(testLoadedObjectInfo, testSymbols)

	// Test cache hit
	result, found = cache.Get(testLoadedObjectInfo.Id)
	assert.True(t, found)
	assert.Equal(t, testSymbols, result)
}

func TestDynamicSymbolsLRUCache_Add(t *testing.T) {
	loader := InitHostSymbolsLoader(2)
	cache, ok := loader.soCache.(*dynamicSymbolsLRUCache)
	require.True(t, ok)

	testSymbols1 := &Symbols{
		Exported: map[string]bool{"test1": true},
		Imported: map[string]bool{"import1": true},
		Local:    map[string]bool{"local1": true},
	}

	testSymbols2 := &Symbols{
		Exported: map[string]bool{"test2": true},
		Imported: map[string]bool{"import2": true},
		Local:    map[string]bool{"local2": true},
	}

	obj1 := ObjInfo{Id: ObjID{Inode: 1, Device: 1, Ctime: 1}, Path: "/test1.so"}
	obj2 := ObjInfo{Id: ObjID{Inode: 2, Device: 2, Ctime: 2}, Path: "/test2.so"}

	// Add first object
	cache.Add(obj1, testSymbols1)
	result, found := cache.Get(obj1.Id)
	assert.True(t, found)
	assert.Equal(t, testSymbols1, result)

	// Add second object
	cache.Add(obj2, testSymbols2)
	result, found = cache.Get(obj2.Id)
	assert.True(t, found)
	assert.Equal(t, testSymbols2, result)
}

func TestLoadSharedObjectDynamicSymbols(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		result, err := loadSharedObjectDynamicSymbols("/non/existent/file.so")

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid ELF file", func(t *testing.T) {
		// Create a temporary file with invalid ELF content
		tmpFile, err := os.CreateTemp("", "invalid_elf_*.so")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write some non-ELF content
		_, err = tmpFile.WriteString("this is not an ELF file")
		require.NoError(t, err)
		tmpFile.Close()

		result, err := loadSharedObjectDynamicSymbols(tmpFile.Name())

		assert.Error(t, err)
		assert.Nil(t, result)

		// Check that it's an UnsupportedFileError
		var unsupportedErr *UnsupportedFileError
		assert.True(t, errors.As(err, &unsupportedErr))
	})

	t.Run("regular file (not ELF)", func(t *testing.T) {
		// Create a temporary text file
		tmpFile, err := os.CreateTemp("", "not_elf_*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("regular text file")
		require.NoError(t, err)
		tmpFile.Close()

		result, err := loadSharedObjectDynamicSymbols(tmpFile.Name())

		assert.Error(t, err)
		assert.Nil(t, result)

		// Check that it's an UnsupportedFileError
		var unsupportedErr *UnsupportedFileError
		assert.True(t, errors.As(err, &unsupportedErr))
	})
}

func TestParseSymbols_LocalSymbols(t *testing.T) {
	// Test parsing of local symbols (those with non-zero Value)
	localSymbols := []elf.Symbol{
		{Name: "local_func1", Value: 0x1000},
		{Name: "local_func2", Value: 0x2000},
		{Name: "zero_value_func", Value: 0}, // Should be ignored
	}

	result := parseSymbols(localSymbols, []elf.Symbol{})

	assert.Len(t, result.Local, 2)
	assert.True(t, result.Local["local_func1"])
	assert.True(t, result.Local["local_func2"])
	assert.False(t, result.Local["zero_value_func"])
	assert.Empty(t, result.Imported)
	assert.Empty(t, result.Exported)
}

func TestParseSymbols_MixedSymbols(t *testing.T) {
	// Test a mix of local and dynamic symbols
	localSymbols := []elf.Symbol{
		{Name: "local_func", Value: 0x1000},
		{Name: "zero_local", Value: 0},
	}

	dynamicSymbols := []elf.Symbol{
		{Name: "import_func", Library: "libc.so.6", Value: 0},
		{Name: "export_func", Value: 0x3000},
		{Name: "both_func", Value: 0x4000}, // Should be both local and exported
	}

	result := parseSymbols(localSymbols, dynamicSymbols)

	// Local symbols
	assert.Len(t, result.Local, 3) // local_func, export_func, both_func
	assert.True(t, result.Local["local_func"])
	assert.True(t, result.Local["export_func"])
	assert.True(t, result.Local["both_func"])
	assert.False(t, result.Local["zero_local"])

	// Imported symbols
	assert.Len(t, result.Imported, 1)
	assert.True(t, result.Imported["import_func"])

	// Exported symbols
	assert.Len(t, result.Exported, 2) // export_func, both_func
	assert.True(t, result.Exported["export_func"])
	assert.True(t, result.Exported["both_func"])
}

func TestNewSOSymbols(t *testing.T) {
	symbols := NewSOSymbols()

	assert.NotNil(t, symbols.Exported)
	assert.NotNil(t, symbols.Imported)
	assert.NotNil(t, symbols.Local)
	assert.Empty(t, symbols.Exported)
	assert.Empty(t, symbols.Imported)
	assert.Empty(t, symbols.Local)
}

func TestInitUnsupportedFileError(t *testing.T) {
	originalErr := errors.New("original error")
	unsupportedErr := InitUnsupportedFileError(originalErr)

	assert.NotNil(t, unsupportedErr)
	assert.Equal(t, originalErr, unsupportedErr.err)
}

func TestUnsupportedFileError_Error(t *testing.T) {
	originalErr := errors.New("test error message")
	unsupportedErr := InitUnsupportedFileError(originalErr)

	assert.Equal(t, "test error message", unsupportedErr.Error())
}

func TestUnsupportedFileError_Unwrap(t *testing.T) {
	originalErr := errors.New("wrapped error")
	unsupportedErr := InitUnsupportedFileError(originalErr)

	unwrapped := unsupportedErr.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestCopyMap(t *testing.T) {
	original := map[string]bool{
		"key1": true,
		"key2": false,
		"key3": true,
	}

	copied := copyMap(original)

	// Check that all values are copied
	assert.Equal(t, original, copied)

	// Check that it's a different map (modifying one doesn't affect the other)
	copied["key4"] = true
	assert.False(t, original["key4"])
	assert.True(t, copied["key4"])

	// Test with empty map
	emptyOriginal := map[string]bool{}
	emptyCopied := copyMap(emptyOriginal)
	assert.Equal(t, emptyOriginal, emptyCopied)
	assert.Len(t, emptyCopied, 0)
}
