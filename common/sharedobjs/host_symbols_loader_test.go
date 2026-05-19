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

// newTestSymbols builds a *Symbols populated with the given category
// memberships. It is the test-only counterpart of the legacy literal
// constructor `&Symbols{Exported: ..., Imported: ..., Local: ...}`.
func newTestSymbols(local, imported, exported []string) *Symbols {
	s := &Symbols{m: make(map[string]SymbolCategory)}
	for _, name := range local {
		s.add(name, CategoryLocal)
	}
	for _, name := range imported {
		s.add(name, CategoryImported)
	}
	for _, name := range exported {
		s.add(name, CategoryExported)
	}
	return s
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

var testDynamicSymbols = newTestSymbols(nil, []string{"syscall"}, []string{"open", "close"})

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
		Name           string
		Input          []elf.Symbol
		ExpectedImport map[string]bool
		ExpectedExport map[string]bool
	}{
		{
			Name:           "No symbols",
			Input:          []elf.Symbol{},
			ExpectedImport: map[string]bool{},
			ExpectedExport: map[string]bool{},
		},
		{
			Name:           "Full details import symbols",
			Input:          []elf.Symbol{{Name: "__ctype_toupper_loc", Info: 18, Section: elf.SHN_UNDEF + 12, Version: "GLIBC_2.3", Library: "libc.so.6"}},
			ExpectedImport: map[string]bool{"__ctype_toupper_loc": true},
			ExpectedExport: map[string]bool{},
		},
		{
			Name:           "Missing details import symbol",
			Input:          []elf.Symbol{{Name: "cap_to_text", Info: 18, Section: elf.SHN_UNDEF}},
			ExpectedImport: map[string]bool{"cap_to_text": true},
			ExpectedExport: map[string]bool{},
		},
		{
			Name:           "Export import symbol",
			Input:          []elf.Symbol{{Name: "_obstack_memory_used", Info: 18, Section: elf.SHN_UNDEF + 12, Value: 55424, Size: 38}},
			ExpectedImport: map[string]bool{},
			ExpectedExport: map[string]bool{"_obstack_memory_used": true},
		},
		{
			Name: "Mixed symbols",
			Input: []elf.Symbol{
				{Name: "__ctype_toupper_loc", Info: 18, Section: elf.SHN_UNDEF + 12, Version: "GLIBC_2.3", Library: "libc.so.6"},
				{Name: "cap_to_text", Info: 18, Section: elf.SHN_UNDEF},
				{Name: "_obstack_memory_used", Info: 18, Section: elf.SHN_UNDEF + 12, Value: 55424, Size: 38},
			},
			ExpectedImport: map[string]bool{
				"__ctype_toupper_loc": true,
				"cap_to_text":         true,
			},
			ExpectedExport: map[string]bool{
				"_obstack_memory_used": true,
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			dynamicSymbols := parseSymbols([]elf.Symbol{}, testCase.Input)
			assert.Equal(t, fmt.Sprint(testCase.ExpectedImport), fmt.Sprint(dynamicSymbols.View(CategoryImported)))
			assert.Equal(t, fmt.Sprint(testCase.ExpectedExport), fmt.Sprint(dynamicSymbols.View(CategoryExported)))
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

	testSymbols := newTestSymbols(
		[]string{"local_func", "local_var"},
		[]string{"syscall"},
		[]string{"open"},
	)

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
		assert.Equal(t, testSymbols.View(CategoryLocal), result)
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

	testSymbols := newTestSymbols(
		[]string{"local"},
		[]string{"import"},
		[]string{"test"},
	)

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

	testSymbols1 := newTestSymbols([]string{"local1"}, []string{"import1"}, []string{"test1"})
	testSymbols2 := newTestSymbols([]string{"local2"}, []string{"import2"}, []string{"test2"})

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

	local := result.View(CategoryLocal)
	assert.Len(t, local, 2)
	assert.True(t, local["local_func1"])
	assert.True(t, local["local_func2"])
	assert.False(t, local["zero_value_func"])
	assert.Empty(t, result.View(CategoryImported))
	assert.Empty(t, result.View(CategoryExported))
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
	local := result.View(CategoryLocal)
	assert.Len(t, local, 3) // local_func, export_func, both_func
	assert.True(t, local["local_func"])
	assert.True(t, local["export_func"])
	assert.True(t, local["both_func"])
	assert.False(t, local["zero_local"])

	// Imported symbols
	imported := result.View(CategoryImported)
	assert.Len(t, imported, 1)
	assert.True(t, imported["import_func"])

	// Exported symbols
	exported := result.View(CategoryExported)
	assert.Len(t, exported, 2) // export_func, both_func
	assert.True(t, exported["export_func"])
	assert.True(t, exported["both_func"])
}

func TestParseSymbols_OverlapDedupesEntries(t *testing.T) {
	// A symbol that is both Local (static) and Exported (dynamic) should occupy
	// a single internal map entry whose category bits are OR'd together.
	localSymbols := []elf.Symbol{
		{Name: "shared_sym", Value: 0x1000},
	}
	dynamicSymbols := []elf.Symbol{
		{Name: "shared_sym", Value: 0x1000}, // local + exported
	}

	result := parseSymbols(localSymbols, dynamicSymbols)

	assert.Equal(t, 1, result.Len(), "overlapping name must collapse to one entry")
	assert.True(t, result.Has("shared_sym", CategoryLocal))
	assert.True(t, result.Has("shared_sym", CategoryExported))
	assert.False(t, result.Has("shared_sym", CategoryImported))
}

func TestNewSOSymbols(t *testing.T) {
	symbols := NewSOSymbols()

	assert.NotNil(t, symbols.m)
	assert.Equal(t, 0, symbols.Len())
	assert.Empty(t, symbols.View(CategoryLocal))
	assert.Empty(t, symbols.View(CategoryImported))
	assert.Empty(t, symbols.View(CategoryExported))
	assert.Empty(t, symbols.View(CategoryDynamic))
}

func TestSymbols_View(t *testing.T) {
	s := newTestSymbols(
		[]string{"a", "shared"},
		[]string{"b"},
		[]string{"c", "shared"},
	)

	// shared is Local|Exported, so it appears in both views.
	assert.Equal(t, map[string]bool{"a": true, "shared": true}, s.View(CategoryLocal))
	assert.Equal(t, map[string]bool{"b": true}, s.View(CategoryImported))
	assert.Equal(t, map[string]bool{"c": true, "shared": true}, s.View(CategoryExported))
	assert.Equal(t, map[string]bool{"b": true, "c": true, "shared": true}, s.View(CategoryDynamic))

	// View returns a fresh map: mutating it must not change subsequent views.
	v := s.View(CategoryLocal)
	v["new"] = true
	assert.False(t, s.Has("new", CategoryLocal))
}

func TestSymbols_Has(t *testing.T) {
	s := newTestSymbols([]string{"a"}, []string{"b"}, []string{"c"})

	assert.True(t, s.Has("a", CategoryLocal))
	assert.False(t, s.Has("a", CategoryExported))
	assert.True(t, s.Has("b", CategoryImported))
	assert.True(t, s.Has("b", CategoryDynamic))
	assert.True(t, s.Has("c", CategoryExported))
	assert.True(t, s.Has("c", CategoryDynamic))
	assert.False(t, s.Has("missing", CategoryLocal|CategoryImported|CategoryExported))
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
