package derived

import (
	"testing"

	"github.com/aquasecurity/tracee/pkg/events/parsing"
	"github.com/aquasecurity/tracee/pkg/utils/shared_objects"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOExportSymbolEventGenerator_GenerateEvents(t *testing.T) {
	soExSymbolEventSkel := EventSkeleton{
		ID:   2006,
		Name: "so_export_watched_symbols",
		Params: []trace.ArgMeta{
			{Type: "const char*", Name: "loaded_object_path"},
			{Type: "const char*const*", Name: "watched_exported_symbols"},
		},
	}

	type testSO struct {
		so                             SoInstance
		expectedWatchedExportedSymbols []string
	}

	testCases := []struct {
		name           string
		watchedSymbols []string
		loadingSO      testSO
	}{
		{
			name:           "SO with no export symbols",
			watchedSymbols: []string{"open", "close", "write"},
			loadingSO: testSO{
				so: SoInstance{
					SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
					ExportedSymbols:   map[string]bool{},
				},
				expectedWatchedExportedSymbols: []string{},
			},
		},
		{
			name:           "SO with 1 watched export symbols",
			watchedSymbols: []string{"open", "close", "write"},
			loadingSO: testSO{
				so: SoInstance{
					SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
					ExportedSymbols:   map[string]bool{"open": true},
				},
				expectedWatchedExportedSymbols: []string{"open"},
			},
		},
		{
			name:           "SO with multiple watched export symbols",
			watchedSymbols: []string{"open", "close", "write"},
			loadingSO: testSO{
				so: SoInstance{
					SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
					ExportedSymbols: map[string]bool{
						"open":  true,
						"close": true,
						"write": true,
					},
				},
				expectedWatchedExportedSymbols: []string{"open", "close", "write"},
			},
		},
		{
			name:           "SO with partly watched export symbols",
			watchedSymbols: []string{"open", "close", "write"},
			loadingSO: testSO{
				so: SoInstance{
					SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
					ExportedSymbols: map[string]bool{
						"open":  true,
						"close": true,
						"sync":  true,
					},
				},
				expectedWatchedExportedSymbols: []string{"open", "close"},
			},
		},
		{
			name:           "SO with no watched export symbols",
			watchedSymbols: []string{"open", "close", "write"},
			loadingSO: testSO{
				so: SoInstance{
					SoExaminationInfo: shared_objects.SoExaminationInfo{Id: shared_objects.SharedObjectIdentification{Inode: 1}, Path: "1.so"},
					ExportedSymbols: map[string]bool{
						"createdir": true,
						"rmdir":     true,
						"walk":      true,
					},
				},
				expectedWatchedExportedSymbols: []string{},
			},
		},
	}
	pid := 1

	t.Run("UT", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				gen := InitSOExportWatchedSymbolsEventGenerator(soExSymbolEventSkel, testCase.watchedSymbols)
				mockLoader := initLoaderMock()
				mockLoader.addSOSymbols(testCase.loadingSO.so)
				gen.soLoader = mockLoader
				exportSymsEvents, _, err := gen.GenerateEvents(generateSOLoadedEvent(pid, testCase.loadingSO.so.SoExaminationInfo))
				require.NoError(t, err)
				if len(testCase.loadingSO.expectedWatchedExportedSymbols) > 0 {
					assert.Len(t, exportSymsEvents, 1)
					event := exportSymsEvents[0]
					syms, err := parsing.GetEventArgStringArrVal(&event, "watched_exported_symbols")
					require.NoError(t, err)
					assert.ElementsMatch(t, testCase.loadingSO.expectedWatchedExportedSymbols, syms)
				} else {
					assert.Len(t, exportSymsEvents, 0)
				}
			})
		}
	})
}
