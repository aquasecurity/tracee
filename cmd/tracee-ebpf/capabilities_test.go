package main

import (
	"testing"

	"github.com/aquasecurity/libbpfgo/helpers"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/gocapability/capability"
)

type mockOSInfo struct {
	version string
}

func (mOSInfo mockOSInfo) CompareOSBaseKernelRelease(version string) int {
	return helpers.CompareKernelRelease(mOSInfo.version, version)
}

type mockCapabilities struct {
	missingCaps []capability.Cap
}

func (mockCaps *mockCapabilities) Get(which capability.CapType, what capability.Cap) bool {
	for _, mcap := range mockCaps.missingCaps {
		if what == mcap {
			return false
		}
	}
	return true
}
func (mockCaps *mockCapabilities) Empty(which capability.CapType) bool                    { return true }
func (mockCaps *mockCapabilities) Full(which capability.CapType) bool                     { return true }
func (mockCaps *mockCapabilities) Set(which capability.CapType, caps ...capability.Cap)   {}
func (mockCaps *mockCapabilities) Unset(which capability.CapType, caps ...capability.Cap) {}
func (mockCaps *mockCapabilities) Fill(kind capability.CapType)                           {}
func (mockCaps *mockCapabilities) Clear(kind capability.CapType)                          {}
func (mockCaps *mockCapabilities) StringCap(which capability.CapType) string              { return "" }
func (mockCaps *mockCapabilities) String() string                                         { return "" }
func (mockCaps *mockCapabilities) Load() error                                            { return nil }
func (mockCaps *mockCapabilities) Apply(kind capability.CapType) error                    { return nil }

func TestGenerateTraceeEbpfRequiredCapabilities(t *testing.T) {
	traceTestCases := []struct {
		name                 string
		chosenEvents         []string
		ifaces               []string
		expectedCapabilities []capability.Cap
	}{
		{
			name:                 "No events chosen",
			chosenEvents:         []string{},
			expectedCapabilities: []capability.Cap{},
		},
		{
			name:                 "Net event chosen",
			chosenEvents:         []string{"net_packet"},
			ifaces:               []string{"enp0s3"},
			expectedCapabilities: []capability.Cap{capability.CAP_NET_ADMIN},
		},
		{
			name:                 "Init namespaces event chosen",
			chosenEvents:         []string{"init_namespaces"},
			expectedCapabilities: []capability.Cap{capability.CAP_SYS_PTRACE},
		},
	}

	environmentTestCases := []struct {
		name                 string
		kernelVersion        string
		missingCapabilities  []capability.Cap
		expectedCapabilities []capability.Cap
	}{
		{
			name:                "Version 4.19 with all capabilities",
			kernelVersion:       "4.19.0",
			missingCapabilities: []capability.Cap{},
			expectedCapabilities: []capability.Cap{
				capability.CAP_IPC_LOCK,
				capability.CAP_SYS_RESOURCE,
				capability.CAP_SYS_ADMIN,
			},
		},
		{
			name:                "Version 5.17 with all capabilities",
			kernelVersion:       "5.17.0",
			missingCapabilities: []capability.Cap{},
			expectedCapabilities: []capability.Cap{
				capability.CAP_IPC_LOCK,
				capability.CAP_SYS_RESOURCE,
				capability.CAP_SYS_ADMIN,
			},
		},
		{
			name:                "Version 5.17 without CAP_BPF",
			kernelVersion:       "5.17.0",
			missingCapabilities: []capability.Cap{capability.CAP_BPF},
			expectedCapabilities: []capability.Cap{
				capability.CAP_IPC_LOCK,
				capability.CAP_SYS_RESOURCE,
				capability.CAP_SYS_ADMIN,
			},
		},
	}

	for _, envTest := range environmentTestCases {
		t.Run(envTest.name, func(t *testing.T) {
			// Generate environment mockers
			osInfo := mockOSInfo{version: envTest.kernelVersion}
			caps := mockCapabilities{missingCaps: envTest.missingCapabilities}

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

					neededCaps, err := generateTraceeEbpfRequiredCapabilities(osInfo, &cfg, &caps)
					require.NoError(t, err)
					expectedCaps := append(envTest.expectedCapabilities, traceTest.expectedCapabilities...)
					expectedCaps = removeDupCaps(expectedCaps)
					assert.ElementsMatch(t, expectedCaps, neededCaps)
				})
			}
		})
	}
}
