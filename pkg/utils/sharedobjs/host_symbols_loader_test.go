package sharedobjs

import (
	"debug/elf"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type soCacheMock struct {
	get func(ObjID) (*dynamicSymbols, bool)
	add func(obj ObjInfo, dynamicSymbols *dynamicSymbols)
}

func (s soCacheMock) Get(identification ObjID) (*dynamicSymbols, bool) {
	if s.get != nil {
		return s.get(identification)
	}
	return nil, false
}

func (s soCacheMock) Add(obj ObjInfo, dynamicSymbols *dynamicSymbols) {
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

var testDynamicSymbols = &dynamicSymbols{
	Exported: map[string]bool{"open": true, "close": true},
	Imported: map[string]bool{"syscall": true},
}

func TestHostSharedObjectSymbolsLoader_GetDynamicSymbols(t *testing.T) {
	t.Parallel()

	t.Run("Happy flow", func(t *testing.T) {
		t.Parallel()

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*dynamicSymbols, bool) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*dynamicSymbols, bool) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*dynamicSymbols, bool) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
			return nil, errors.New("no SO")
		}
		cache := soCacheMock{
			get: func(identification ObjID) (*dynamicSymbols, bool) {
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

		failLoadingFunc := func(path string) (*dynamicSymbols, error) {
			return nil, errors.New("no SO")
		}
		cachedSymbols := make(map[ObjInfo]*dynamicSymbols)
		cache := soCacheMock{
			add: func(obj ObjInfo, dynamicSymbols *dynamicSymbols) {
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

		cachedSymbols := make(map[ObjInfo]*dynamicSymbols)
		cache := soCacheMock{
			add: func(obj ObjInfo, dynamicSymbols *dynamicSymbols) {
				cachedSymbols[obj] = dynamicSymbols
			},
		}
		soLoader := HostSymbolsLoader{
			loadingFunc: func(path string) (*dynamicSymbols, error) {
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
		ExpecteResult dynamicSymbols
	}{
		{
			Name:          "No symbols",
			Input:         []elf.Symbol{},
			ExpecteResult: NewSOSymbols(),
		},
		{
			Name:  "Full details import symbols",
			Input: []elf.Symbol{{Name: "__ctype_toupper_loc", Info: 18, Section: elf.SHN_UNDEF + 12, Version: "GLIBC_2.3", Library: "libc.so.6"}},
			ExpecteResult: dynamicSymbols{
				Exported: make(map[string]bool),
				Imported: map[string]bool{
					"__ctype_toupper_loc": true,
				},
			},
		},
		{
			Name:  "Missing details import symbol",
			Input: []elf.Symbol{{Name: "cap_to_text", Info: 18, Section: elf.SHN_UNDEF}},
			ExpecteResult: dynamicSymbols{
				Exported: make(map[string]bool),
				Imported: map[string]bool{
					"cap_to_text": true,
				},
			},
		},
		{
			Name:  "Export import symbol",
			Input: []elf.Symbol{{Name: "_obstack_memory_used", Info: 18, Section: elf.SHN_UNDEF + 12, Value: 55424, Size: 38}},
			ExpecteResult: dynamicSymbols{
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
			ExpecteResult: dynamicSymbols{
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

			dynamicSymbols := parseDynamicSymbols(testCase.Input)
			assert.Equal(t, fmt.Sprint(testCase.ExpecteResult.Imported), fmt.Sprint(dynamicSymbols.Imported))
			assert.Equal(t, fmt.Sprint(testCase.ExpecteResult.Exported), fmt.Sprint(dynamicSymbols.Exported))
		})
	}
}
