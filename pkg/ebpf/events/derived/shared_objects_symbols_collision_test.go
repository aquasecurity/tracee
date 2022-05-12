package derived

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/events/parsing"
	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type symbolsLoaderMock struct {
	cache map[shared_objects.SoExaminationInfo]map[string]bool
}

func initLoaderMock() symbolsLoaderMock {
	return symbolsLoaderMock{cache: make(map[shared_objects.SoExaminationInfo]map[string]bool)}
}

func (loader symbolsLoaderMock) GetSOExSymbols(info shared_objects.SoExaminationInfo) (map[string]bool, error) {
	return loader.cache[info], nil
}

func (loader symbolsLoaderMock) addSOSymbols(info SoInstance) {
	loader.cache[info.SoExaminationInfo] = info.ExportedSymbols
}

func generateSOLoadedEvent(pid int, so shared_objects.SoExaminationInfo) trace.Event {
	return trace.Event{
		EventName:     "shared_object_loaded",
		EventID:       1036,
		HostProcessID: pid,
		ProcessID:     pid,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Type: "const char*", Name: "pathname"}, Value: so.Path},
			{ArgMeta: trace.ArgMeta{Type: "int", Name: "flags"}, Value: 0},
			{ArgMeta: trace.ArgMeta{Type: "dev_t", Name: "dev"}, Value: so.Id.Device},
			{ArgMeta: trace.ArgMeta{Type: "unsigned long", Name: "inode"}, Value: so.Id.Inode},
			{ArgMeta: trace.ArgMeta{Type: "unsigned long", Name: "ctime"}, Value: so.Id.Ctime},
		},
	}
}

func TestGetCollisions(t *testing.T) {
	soColEventSkel := EventSkeleton{
		ID:   1037,
		Name: "shared_object_export_collision",
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "loaded_object_path"},
			{Type: "const char*", Name: "collided_object_path"},
			{Type: "const char*const*", Name: "collision_symbols"},
		},
	}

	testCases := []struct {
		name            string
		loadingSO       SoInstance
		loadedSO        SoInstance
		expectedResults []string
	}{
		{
			name: "One symbol which collides",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			loadedSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			expectedResults: []string{"open"},
		},
		{
			name: "One symbols which doesn't collide",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"write": true},
			},
			loadedSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
				ExportedSymbols:   map[string]bool{"ioctl": true},
			},
			expectedResults: nil,
		},
		{
			name: "Multiple symbols which part of them collide",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true, "write": true},
			},
			loadedSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
				ExportedSymbols:   map[string]bool{"open": true, "ioctl": true},
			},
			expectedResults: []string{"open"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			loader := shared_objects.InitSOExSymbolsLoader(1024)
			gen := InitSOCollisionsEventGenerator(soColEventSkel, loader)
			mockLoader := initLoaderMock()
			mockLoader.addSOSymbols(testCase.loadingSO)
			mockLoader.addSOSymbols(testCase.loadedSO)
			gen.soLoader = mockLoader
			col, err := gen.findSOCollisions(&testCase.loadingSO, testCase.loadedSO.SoExaminationInfo)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedResults, col)
		})
	}
}

func TestGenerateEvents(t *testing.T) {
	soColEventSkel := EventSkeleton{
		ID:   1037,
		Name: "shared_object_export_collision",
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "loaded_object_path"},
			{Type: "const char*", Name: "collided_object_path"},
			{Type: "const char*const*", Name: "collision_symbols"},
		},
	}

	type testSO struct {
		so                 SoInstance
		expectedCollisions []string
	}

	testCases := []struct {
		name      string
		loadingSO SoInstance
		loadedSOs []testSO
	}{
		{
			name: "One loaded SO which collides",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "One loaded SO which doesn't collide",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "One loaded SO which collides partly",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"open": true, "write": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which collides",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 3}, Path: "3.so"},
						ExportedSymbols:   map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
			},
		},
		{
			name: "Multiple loaded SO which doesn't collide",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 3}, Path: "3.so"},
						ExportedSymbols:   map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{},
				},
			},
		},
		{
			name: "Multiple loaded SO which partly collide",
			loadingSO: SoInstance{
				SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
				ExportedSymbols:   map[string]bool{"open": true, "ioctl": true},
			},
			loadedSOs: []testSO{
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 2}, Path: "2.so"},
						ExportedSymbols:   map[string]bool{"write": true},
					},
					expectedCollisions: []string{},
				},
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 3}, Path: "3.so"},
						ExportedSymbols:   map[string]bool{"open": true},
					},
					expectedCollisions: []string{"open"},
				},
				{
					so: SoInstance{
						SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 4}, Path: "4.so"},
						ExportedSymbols:   map[string]bool{"ioctl": true},
					},
					expectedCollisions: []string{"ioctl"},
				},
			},
		},
	}
	pid := 1

	t.Run("UT", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				loader := shared_objects.InitSOExSymbolsLoader(1024)
				gen := InitSOCollisionsEventGenerator(soColEventSkel, loader)
				mockLoader := initLoaderMock()
				mockLoader.addSOSymbols(testCase.loadingSO)
				loadedSOs := make([]shared_objects.SoExaminationInfo, len(testCase.loadedSOs))
				for i, lso := range testCase.loadedSOs {
					mockLoader.addSOSymbols(lso.so)
					loadedSOs[i] = lso.so.SoExaminationInfo
				}
				gen.soLoader = mockLoader
				gen.processesSOsCache.SetProcessLoadedObjects(pid, loadedSOs)
				colEvents, _, err := gen.GenerateEvents(generateSOLoadedEvent(pid, testCase.loadingSO.SoExaminationInfo))
				require.NoError(t, err)
				for _, lso := range testCase.loadedSOs {
					if len(lso.expectedCollisions) > 0 {
						found := false
						for _, e := range colEvents {
							path, err := parsing.GetEventArgStringVal(&e, "collided_object_path")
							require.NoError(t, err)
							if path == lso.so.Path {
								col, err := parsing.GetEventArgStringArrVal(&e, "collision_symbols")
								require.NoError(t, err)
								assert.Equal(t, col, lso.expectedCollisions)
								found = true
								break
							}
						}
						assert.True(t, found)
					}
				}
			})
		}
	})

	t.Run("Integration", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				loader := shared_objects.InitSOExSymbolsLoader(1024)
				gen := InitSOCollisionsEventGenerator(soColEventSkel, loader)
				mockLoader := initLoaderMock()
				gen.soLoader = mockLoader
				mockLoader.addSOSymbols(testCase.loadingSO)
				for _, lso := range testCase.loadedSOs {
					mockLoader.addSOSymbols(lso.so)
					_, _, err := gen.GenerateEvents(generateSOLoadedEvent(pid, lso.so.SoExaminationInfo))
					require.NoError(t, err)
				}
				colEvents, _, err := gen.GenerateEvents(generateSOLoadedEvent(pid, testCase.loadingSO.SoExaminationInfo))
				require.NoError(t, err)
				for _, lso := range testCase.loadedSOs {
					if len(lso.expectedCollisions) > 0 {
						found := false
						for _, e := range colEvents {
							path, err := parsing.GetEventArgStringVal(&e, "collided_object_path")
							require.NoError(t, err)
							if path == lso.so.Path {
								col, err := parsing.GetEventArgStringArrVal(&e, "collision_symbols")
								require.NoError(t, err)
								assert.Equal(t, col, lso.expectedCollisions)
								found = true
								break
							}
						}
						assert.True(t, found)
					}
				}
			})
		}
	})
}
