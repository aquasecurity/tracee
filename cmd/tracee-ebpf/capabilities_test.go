package main

import (
	"testing"

	"github.com/aquasecurity/libbpfgo/helpers"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type mockOSInfo struct {
	version string
}

func (mOSInfo mockOSInfo) CompareOSBaseKernelRelease(version string) int {
	return helpers.CompareKernelRelease(mOSInfo.version, version)
}

func TestGenerateTraceeEbpfRequiredCapabilities(t *testing.T) {
	traceTestCases := []struct {
		name                 string
		chosenEvents         []string
		ifaces               []string
		expectedCapabilities []cap.Value
	}{
		{
			name:                 "No events chosen",
			chosenEvents:         []string{},
			expectedCapabilities: []cap.Value{},
		},
		{
			name:                 "Net event chosen",
			chosenEvents:         []string{"net_packet"},
			ifaces:               []string{"enp0s3"},
			expectedCapabilities: []cap.Value{cap.NET_ADMIN},
		},
		{
			name:                 "Init namespaces event chosen",
			chosenEvents:         []string{"init_namespaces"},
			expectedCapabilities: []cap.Value{cap.SYS_PTRACE},
		},
	}

	environmentTestCases := []struct {
		name                 string
		kernelVersion        string
		missingCapabilities  []cap.Value
		expectedCapabilities []cap.Value
	}{
		{
			name:                "Version 4.19 with all capabilities",
			kernelVersion:       "4.19.0",
			missingCapabilities: []cap.Value{},
			expectedCapabilities: []cap.Value{
				cap.IPC_LOCK,
				cap.SYS_RESOURCE,
				cap.SYS_ADMIN,
			},
		},
		{
			name:                "Version 5.17 with all capabilities",
			kernelVersion:       "5.17.0",
			missingCapabilities: []cap.Value{},
			expectedCapabilities: []cap.Value{
				cap.IPC_LOCK,
				cap.SYS_RESOURCE,
				cap.SYS_ADMIN,
			},
		},
		{
			name:                "Version 5.17 without CAP_BPF",
			kernelVersion:       "5.17.0",
			missingCapabilities: []cap.Value{cap.BPF},
			expectedCapabilities: []cap.Value{
				cap.IPC_LOCK,
				cap.SYS_RESOURCE,
				cap.SYS_ADMIN,
			},
		},
	}

	for _, envTest := range environmentTestCases {
		t.Run(envTest.name, func(t *testing.T) {
			// Generate environment mockers
			osInfo := mockOSInfo{version: envTest.kernelVersion}

			for _, traceTest := range traceTestCases {
				t.Run(traceTest.name, func(t *testing.T) {
					// Create configuration for given tracing
					eventsToTrace := make([]events.ID, len(traceTest.chosenEvents))
					eventsNameToID := events.Definitions.NamesToIDs()
					for _, eventName := range traceTest.chosenEvents {
						eventsToTrace = append(eventsToTrace, eventsNameToID[eventName])
					}
					cfg := tracee.Config{
						Filter: &tracee.Filter{
							EventsToTrace: eventsToTrace,
							NetFilter: &tracee.IfaceFilter{
								InterfacesToTrace: traceTest.ifaces,
							},
						},
						Capture: &tracee.CaptureConfig{},
						Debug:   false,
					}

					neededCaps, err := generateTraceeEbpfRequiredCapabilities(osInfo, &cfg)
					require.NoError(t, err)
					expectedCaps := append(envTest.expectedCapabilities, traceTest.expectedCapabilities...)
					expectedCaps = removeDupCaps(expectedCaps)
					assert.ElementsMatch(t, expectedCaps, neededCaps)
				})
			}
		})
	}
}
