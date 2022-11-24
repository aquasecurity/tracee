package derive

import (
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSO struct {
	so                 loadingSOInstance
	expectedCollisions []string
}

func getSymbolsCollisionTestCases() []struct {
	name      string
	blackList []string
	whiteList []string
	loadingSO loadingSOInstance
	loadedSOs []testSO
} {
	return []struct {
		name      string
		blackList []string
		whiteList []string
		loadingSO loadingSOInstance
		loadedSOs []testSO
	}{
		{
			name: "One loaded SO which collides",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "One loaded SO which doesn't collide",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "One loaded SO which collides partly",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which collides",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 3}, Path: "3.so"},
						ExportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which doesn't collide",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 3}, Path: "3.so"},
						ExportedSymbols: map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "Multiple loaded SO which partly collide",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 3}, Path: "3.so"},
						ExportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 4}, Path: "4.so"},
						ExportedSymbols: map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{"ioctl"},
				},
			},
		},
		{
			name: "Collision which is partly filtered in",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "write": true},
			},
			blackList: []string{"open"},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Collision which is partly filtered out",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "write": true},
			},
			whiteList: []string{"write"},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Collision which is filtered out",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "write": true},
			},
			whiteList: []string{"open", "write"},
			loadedSOs: []testSO{
				{
					so: loadingSOInstance{
						ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
						ExportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
	}
}

func TestSymbolsCollisionArgsGenerator_FindSOCollision(t *testing.T) {
	testCases := []struct {
		name            string
		loadingSO       loadingSOInstance
		loadedSO        loadingSOInstance
		expectedResults []string
	}{
		{
			name: "One symbol which collides",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			loadedSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				ExportedSymbols: map[string]bool{"open": true},
			},
			expectedResults: []string{"open"},
		},
		{
			name: "One symbols which doesn't collide",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"write": true},
			},
			loadedSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				ExportedSymbols: map[string]bool{"ioctl": true},
			},
			expectedResults: nil,
		},
		{
			name: "Multiple symbols which part of them collide",
			loadingSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				ExportedSymbols: map[string]bool{"open": true, "write": true},
			},
			loadedSO: loadingSOInstance{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				ExportedSymbols: map[string]bool{"open": true, "ioctl": true},
			},
			expectedResults: []string{"open"},
		},
	}
	filtersTestCases := []struct {
		name      string
		whiteList []string
		blackList []string
	}{
		{
			name: "No filters",
		},
		{
			name:      "Collision whitelisted",
			whiteList: []string{"open"},
		},
		{
			name:      "Collision blacklisted",
			blackList: []string{"open"},
		},
		{
			name:      "Collided filters",
			whiteList: []string{"open"},
			blackList: []string{"open"},
		},
		{
			name:      "Unrelated filters",
			whiteList: []string{"write", "read"},
			blackList: []string{"ioctl", "splice"},
		},
	}

	listContains := func(list []string, node string) bool {
		for _, i := range list {
			if i == node {
				return true
			}
		}
		return false
	}

	copyListFiltered := func(list []string, filterIn []string, filterOut []string) []string {
		var newList []string
		for _, node := range list {
			if len(filterIn) == 0 || listContains(filterIn, node) {
				if !listContains(filterOut, node) {
					newList = append(newList, node)
				}
			}
		}
		return newList
	}

	for _, filterTestCase := range filtersTestCases {
		t.Run(filterTestCase.name, func(t *testing.T) {
			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					mockLoader := initLoaderMock(false)
					gen := initSOCollisionsEventGenerator(mockLoader, filterTestCase.blackList, filterTestCase.whiteList)
					mockLoader.addSOSymbols(testSOInstance{info: testCase.loadingSO.ObjInfo, syms: testCase.loadingSO.GetSymbols()})
					mockLoader.addSOSymbols(testSOInstance{info: testCase.loadedSO.ObjInfo, syms: testCase.loadedSO.GetSymbols()})
					gen.soLoader = mockLoader
					collisions, err := gen.findSOCollisions(&testCase.loadingSO, testCase.loadedSO.ObjInfo)
					require.NoError(t, err)
					for _, collision := range collisions {
						if len(filterTestCase.blackList) > 0 {
							assert.Contains(t, filterTestCase.blackList, collision)
						}
						assert.NotContains(t, filterTestCase.whiteList, collision)
					}
					expectedResults := copyListFiltered(testCase.expectedResults, filterTestCase.blackList, filterTestCase.whiteList)
					assert.ElementsMatch(t, expectedResults, collisions)
				})
			}
		})
	}
}

func TestSymbolsCollisionArgsGenerator_deriveArgs(t *testing.T) {
	testCases := getSymbolsCollisionTestCases()
	pid := 1

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockLoader := initLoaderMock(false)
			gen := initSOCollisionsEventGenerator(mockLoader, testCase.blackList, testCase.whiteList)
			mockLoader.addSOSymbols(testSOInstance{info: testCase.loadingSO.ObjInfo, syms: testCase.loadingSO.GetSymbols()})

			// Init cache for test
			loadedSOs := make([]sharedobjs.ObjInfo, len(testCase.loadedSOs))
			for i, lso := range testCase.loadedSOs {
				mockLoader.addSOSymbols(testSOInstance{info: lso.so.ObjInfo, syms: lso.so.GetSymbols()})
				loadedSOs[i] = lso.so.ObjInfo
			}
			gen.processesSOsCache.SetProcessLoadedObjects(pid, loadedSOs)

			colEventsArgs, errs := gen.deriveArgs(generateSOLoadedEvent(pid, testCase.loadingSO.ObjInfo))
			require.Empty(t, errs)
			for _, lso := range testCase.loadedSOs {
				if len(lso.expectedCollisions) > 0 {
					found := false
					for _, args := range colEventsArgs {
						require.Len(t, args, 3)
						assert.Equal(t, testCase.loadingSO.Path, args[0])
						path := args[1]
						require.IsType(t, "", path)
						path = path.(string)
						if path == lso.so.Path {
							col := args[2]
							require.IsType(t, []string{}, col)
							col = col.([]string)
							assert.ElementsMatch(t, col, lso.expectedCollisions)
							found = true
							break
						}
					}
					assert.True(t, found)
				}
			}
		})
	}
}

func TestSymbolsCollision(t *testing.T) {
	testCases := getSymbolsCollisionTestCases()
	pid := 1

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockLoader := initLoaderMock(false)
			deriveFunc := SymbolsCollision(mockLoader, testCase.blackList, testCase.whiteList)
			mockLoader.addSOSymbols(testSOInstance{info: testCase.loadingSO.ObjInfo, syms: testCase.loadingSO.GetSymbols()})

			// Parse loading events to initialize cache
			for _, lso := range testCase.loadedSOs {
				mockLoader.addSOSymbols(testSOInstance{info: lso.so.ObjInfo, syms: lso.so.GetSymbols()})
				_, errs := deriveFunc(generateSOLoadedEvent(pid, lso.so.ObjInfo))
				require.Empty(t, errs)
			}

			colEvents, errs := deriveFunc(generateSOLoadedEvent(pid, testCase.loadingSO.ObjInfo))
			require.Empty(t, errs)
			for _, lso := range testCase.loadedSOs {
				if len(lso.expectedCollisions) > 0 {
					found := false
					for _, event := range colEvents {
						require.Len(t, event.Args, 3)
						loadingSOPath, err := parse.ArgVal[string](&event, "loaded_path")
						require.NoError(t, err)
						assert.Equal(t, testCase.loadingSO.Path, loadingSOPath)
						collidedSOPath, err := parse.ArgVal[string](&event, "collision_path")
						require.NoError(t, err)
						require.IsType(t, "", collidedSOPath)
						if collidedSOPath == lso.so.Path {
							col, err := parse.ArgVal[[]string](&event, "symbols")
							require.NoError(t, err)
							assert.ElementsMatch(t, col, lso.expectedCollisions)
							found = true
							break
						}
					}
					assert.True(t, found)
				}
			}
		})
	}
}
