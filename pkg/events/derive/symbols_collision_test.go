package derive

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
)

type testSO struct {
	so                 loadingSharedObj
	expectedCollisions []string
}

func getSymbolsCollisionTestCases() []struct {
	name      string
	blackList []string
	whiteList []string
	loadingSO loadingSharedObj
	loadedSOs []testSO
} {
	return []struct {
		name      string
		blackList []string
		whiteList []string
		loadingSO loadingSharedObj
		loadedSOs []testSO
	}{
		{
			name: "One loaded SO which collides",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "One loaded SO which doesn't collide",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "One loaded SO which collides partly",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which collides",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 3},
							Path: "3.so",
						},
						exportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which doesn't collide",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 3},
							Path: "3.so",
						},
						exportedSymbols: map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "Multiple loaded SO which partly collide",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 3},
							Path: "3.so",
						},
						exportedSymbols: map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 4},
							Path: "4.so",
						},
						exportedSymbols: map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{"ioctl"},
				},
			},
		},
		{
			name: "Collision which is partly filtered in",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "write": true},
			},
			blackList: []string{"open"},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Collision which is partly filtered out",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "write": true},
			},
			whiteList: []string{"write"},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Collision which is filtered out",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "write": true},
			},
			whiteList: []string{"open", "write"},
			loadedSOs: []testSO{
				{
					so: loadingSharedObj{
						ObjInfo: sharedobjs.ObjInfo{
							Id:   sharedobjs.ObjID{Inode: 2},
							Path: "2.so",
						},
						exportedSymbols: map[string]bool{"open": true, "write": true},
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
		loadingSO       loadingSharedObj
		loadedSO        loadingSharedObj
		expectedResults []string
	}{
		{
			name: "One symbol which collides",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			loadedSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				exportedSymbols: map[string]bool{"open": true},
			},
			expectedResults: []string{"open"},
		},
		{
			name: "One symbols which doesn't collide",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"write": true},
			},
			loadedSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				exportedSymbols: map[string]bool{"ioctl": true},
			},
			expectedResults: nil,
		},
		{
			name: "Multiple symbols which part of them collide",
			loadingSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 1}, Path: "1.so"},
				exportedSymbols: map[string]bool{"open": true, "write": true},
			},
			loadedSO: loadingSharedObj{
				ObjInfo:         sharedobjs.ObjInfo{Id: sharedobjs.ObjID{Inode: 2}, Path: "2.so"},
				exportedSymbols: map[string]bool{"open": true, "ioctl": true},
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
		filterTestCase := filterTestCase

		t.Run(filterTestCase.name, func(t *testing.T) {
			t.Parallel()

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					mockLoader := initLoaderMock(nil)
					gen := initSOCollisionsEventGenerator(
						mockLoader,
						filterTestCase.blackList,
						filterTestCase.whiteList,
					)
					mockLoader.addSOSymbols(
						testSOInstance{
							info: testCase.loadingSO.ObjInfo,
							syms: testCase.loadingSO.GetSymbols(),
						},
					)
					mockLoader.addSOSymbols(
						testSOInstance{
							info: testCase.loadedSO.ObjInfo,
							syms: testCase.loadedSO.GetSymbols(),
						},
					)
					gen.soLoader = mockLoader
					collisions, err := gen.findShObjsCollisions(
						&testCase.loadingSO,
						testCase.loadedSO.ObjInfo,
					)
					require.NoError(t, err)
					for _, collision := range collisions {
						if len(filterTestCase.blackList) > 0 {
							assert.Contains(t, filterTestCase.blackList, collision)
						}
						assert.NotContains(t, filterTestCase.whiteList, collision)
					}
					expectedResults := copyListFiltered(
						testCase.expectedResults,
						filterTestCase.blackList,
						filterTestCase.whiteList,
					)
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
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			mockLoader := initLoaderMock(nil)
			gen := initSOCollisionsEventGenerator(
				mockLoader,
				testCase.blackList,
				testCase.whiteList,
			)
			mockLoader.addSOSymbols(
				testSOInstance{
					info: testCase.loadingSO.ObjInfo,
					syms: testCase.loadingSO.GetSymbols(),
				},
			)

			// Init cache for test
			loadedSOs := make([]sharedobjs.ObjInfo, len(testCase.loadedSOs))
			for i, lso := range testCase.loadedSOs {
				mockLoader.addSOSymbols(
					testSOInstance{info: lso.so.ObjInfo, syms: lso.so.GetSymbols()},
				)
				loadedSOs[i] = lso.so.ObjInfo
			}
			gen.loadedObjsPerProcCache.SetProcessLoadedObjects(pid, loadedSOs)

			colEventsArgs, errs := gen.deriveArgs(
				generateSOLoadedEvent(pid, testCase.loadingSO.ObjInfo),
			)
			require.Empty(t, errs)
			for _, lso := range testCase.loadedSOs {
				if len(lso.expectedCollisions) > 0 {
					found := false
					for _, args := range colEventsArgs {
						require.Len(t, args, 3)
						assert.Equal(t, testCase.loadingSO.Path, args[0])
						path := args[1]
						require.IsType(t, "", path)
						path, ok := path.(string)
						if !ok {
							t.Error("Failed to cast path's value")
						}
						if path == lso.so.Path {
							col := args[2]
							require.IsType(t, []string{}, col)
							col, ok = col.([]string)
							if !ok {
								t.Error("Failed to cast path arg's value")
							}
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
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			mockLoader := initLoaderMock(nil)

			// Prepare mocked filters for the existing test cases

			filterName := "symbols_collision.data.symbols"
			eventsNameToID := map[string]events.ID{"symbols_collision": events.SymbolsCollision}

			p := policy.NewPolicy()
			p.EventsToTrace = map[events.ID]string{events.SymbolsCollision: "symbols_collision"}

			if len(testCase.blackList) > 0 {
				operAndValsBlack := fmt.Sprintf("!=%s", strings.Join(testCase.blackList, ","))
				err := p.DataFilter.Parse(filterName, operAndValsBlack, eventsNameToID)
				require.NoError(t, err)
			}
			if len(testCase.whiteList) > 0 {
				operAndValsWhite := fmt.Sprintf("=%s", strings.Join(testCase.whiteList, ","))
				err := p.DataFilter.Parse(filterName, operAndValsWhite, eventsNameToID)
				require.NoError(t, err)
			}

			pManager := policy.NewPolicyManager(p)

			// Pick derive function from mocked tests
			deriveFunc := SymbolsCollision(mockLoader, pManager)

			mockLoader.addSOSymbols(
				testSOInstance{
					info: testCase.loadingSO.ObjInfo,
					syms: testCase.loadingSO.GetSymbols(),
				},
			)

			// Parse loading events to initialize cache
			for _, lso := range testCase.loadedSOs {
				mockLoader.addSOSymbols(
					testSOInstance{info: lso.so.ObjInfo, syms: lso.so.GetSymbols()},
				)
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
						loadingSOPath, err := parse.ArgVal[string](event.Args, "loaded_path")
						require.NoError(t, err)
						assert.Equal(t, testCase.loadingSO.Path, loadingSOPath)
						collidedSOPath, err := parse.ArgVal[string](event.Args, "collision_path")
						require.NoError(t, err)
						require.IsType(t, "", collidedSOPath)
						if collidedSOPath == lso.so.Path {
							col, err := parse.ArgVal[[]string](event.Args, "symbols")
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
