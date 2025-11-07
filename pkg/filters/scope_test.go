package filters

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/filters/sets"
)

func TestScopeFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewScopeFilter()
	err := filter.Parse(ScopeProcessorID, "=0")
	require.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		ScopeFilter{},
		NumericFilter[int64]{},
		NumericFilter[uint64]{},
		BoolFilter{},
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	if !cmp.Equal(filter, copy, opt1) {
		diff := cmp.Diff(filter, copy, opt1)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse(ScopePID, "=1")
	require.NoError(t, err)
	if cmp.Equal(filter, copy, opt1) {
		t.Errorf("Changes to copied filter affected the original")
	}
}

func TestScopeFilterHasScopeFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupFilter    func(*ScopeFilter) error
		scopeToCheck   ScopeName
		expectedResult bool
	}{
		// ========================================
		// Cases expecting TRUE (scope is filtered)
		// ========================================

		// Boolean scope filters
		{
			name: "container scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainer, "")
			},
			scopeToCheck:   ScopeContainer,
			expectedResult: true,
		},
		{
			name: "host scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHost, "")
			},
			scopeToCheck:   ScopeHost,
			expectedResult: true,
		},

		// Process ID scope filters
		{
			name: "pid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePID, "=1234")
			},
			scopeToCheck:   ScopePID,
			expectedResult: true,
		},
		{
			name: "pid alias 'p' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeP, "=5678")
			},
			scopeToCheck:   ScopeP,
			expectedResult: true,
		},
		{
			name: "pid alias 'processId' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeProcessID, "=9999")
			},
			scopeToCheck:   ScopeProcessID,
			expectedResult: true,
		},
		{
			name: "tid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeTID, "=5678")
			},
			scopeToCheck:   ScopeTID,
			expectedResult: true,
		},
		{
			name: "tid alias 'threadId' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeThreadID, "=1111")
			},
			scopeToCheck:   ScopeThreadID,
			expectedResult: true,
		},
		{
			name: "ppid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePPID, "=1")
			},
			scopeToCheck:   ScopePPID,
			expectedResult: true,
		},
		{
			name: "hostPid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHostPID, "=12345")
			},
			scopeToCheck:   ScopeHostPID,
			expectedResult: true,
		},
		{
			name: "hostTid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHostTID, "=54321")
			},
			scopeToCheck:   ScopeHostTID,
			expectedResult: true,
		},
		{
			name: "hostPpid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHostPPID, "=1")
			},
			scopeToCheck:   ScopeHostPPID,
			expectedResult: true,
		},

		// User scope filters
		{
			name: "uid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeUID, "=1000")
			},
			scopeToCheck:   ScopeUID,
			expectedResult: true,
		},
		{
			name: "uid alias 'userId' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeUserID, "=1001")
			},
			scopeToCheck:   ScopeUserID,
			expectedResult: true,
		},

		// Namespace scope filters
		{
			name: "mntns scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeMntNS, "=4026531840")
			},
			scopeToCheck:   ScopeMntNS,
			expectedResult: true,
		},
		{
			name: "mntns alias 'mountNamespace' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeMountNamespace, "=4026531841")
			},
			scopeToCheck:   ScopeMountNamespace,
			expectedResult: true,
		},
		{
			name: "pidns scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePidNS, "=4026531836")
			},
			scopeToCheck:   ScopePidNS,
			expectedResult: true,
		},
		{
			name: "pidns alias 'pidNamespace' enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePidNamespace, "=4026531837")
			},
			scopeToCheck:   ScopePidNamespace,
			expectedResult: true,
		},

		// Process name scope filters
		{
			name: "comm scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeComm, "=bash")
			},
			scopeToCheck:   ScopeComm,
			expectedResult: true,
		},
		{
			name: "processName alias for comm",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeProcessName, "=zsh")
			},
			scopeToCheck:   ScopeProcessName,
			expectedResult: true,
		},

		// Host scope filter
		{
			name: "hostName scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHostName, "=myhost")
			},
			scopeToCheck:   ScopeHostName,
			expectedResult: true,
		},

		// Cgroup scope filter
		{
			name: "cgroupId scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeCgroupID, "=123456")
			},
			scopeToCheck:   ScopeCgroupID,
			expectedResult: true,
		},

		// Container attribute scope filters
		{
			name: "containerId scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainerID, "=abc123def456")
			},
			scopeToCheck:   ScopeContainerID,
			expectedResult: true,
		},
		{
			name: "containerImage scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainerImage, "=nginx:latest")
			},
			scopeToCheck:   ScopeContainerImage,
			expectedResult: true,
		},
		{
			name: "containerName scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainerName, "=my-container")
			},
			scopeToCheck:   ScopeContainerName,
			expectedResult: true,
		},
		{
			name: "containerImageDigest scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainerImageDigest, "=sha256:abc123")
			},
			scopeToCheck:   ScopeContainerImageDigest,
			expectedResult: true,
		},

		// Kubernetes pod scope filters
		{
			name: "podName scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePodName, "=my-pod")
			},
			scopeToCheck:   ScopePodName,
			expectedResult: true,
		},
		{
			name: "podNamespace scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePodNamespace, "=default")
			},
			scopeToCheck:   ScopePodNamespace,
			expectedResult: true,
		},
		{
			name: "podNs alias for podNamespace enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePodNs, "=kube-system")
			},
			scopeToCheck:   ScopePodNs,
			expectedResult: true,
		},
		{
			name: "podUid scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePodUID, "=abc-123-def-456")
			},
			scopeToCheck:   ScopePodUID,
			expectedResult: true,
		},
		{
			name: "podSandbox scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePodSandbox, "=true")
			},
			scopeToCheck:   ScopePodSandbox,
			expectedResult: true,
		},

		// Other scope filters
		{
			name: "syscall scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeSyscall, "=openat")
			},
			scopeToCheck:   ScopeSyscall,
			expectedResult: true,
		},
		{
			name: "timestamp scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeTimestamp, ">1234567890")
			},
			scopeToCheck:   ScopeTimestamp,
			expectedResult: true,
		},
		{
			name: "processorId scope enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeProcessorID, "=0")
			},
			scopeToCheck:   ScopeProcessorID,
			expectedResult: true,
		},

		// Multiple scopes enabled
		{
			name: "multiple scopes enabled - check first",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				if err := f.Parse(ScopeUID, "=1000"); err != nil {
					return err
				}
				return f.Parse(ScopeComm, "=bash")
			},
			scopeToCheck:   ScopePID,
			expectedResult: true,
		},
		{
			name: "multiple scopes enabled - check middle",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				if err := f.Parse(ScopeUID, "=1000"); err != nil {
					return err
				}
				return f.Parse(ScopeComm, "=bash")
			},
			scopeToCheck:   ScopeUID,
			expectedResult: true,
		},
		{
			name: "multiple scopes enabled - check last",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				if err := f.Parse(ScopeUID, "=1000"); err != nil {
					return err
				}
				return f.Parse(ScopeComm, "=bash")
			},
			scopeToCheck:   ScopeComm,
			expectedResult: true,
		},

		// ========================================
		// Cases expecting FALSE (scope is NOT filtered)
		// ========================================

		{
			name: "scope not enabled - checking uid when only pid enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePID, "=1234")
			},
			scopeToCheck:   ScopeUID,
			expectedResult: false,
		},
		{
			name: "scope not enabled - checking container when only host enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeHost, "")
			},
			scopeToCheck:   ScopeContainer,
			expectedResult: false,
		},
		{
			name: "scope not enabled - checking comm when only pid enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePID, "=1234")
			},
			scopeToCheck:   ScopeComm,
			expectedResult: false,
		},
		{
			name: "scope not enabled - checking syscall when only uid enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeUID, "=1000")
			},
			scopeToCheck:   ScopeSyscall,
			expectedResult: false,
		},
		{
			name: "scope not enabled - checking podName when only containerId enabled",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainerID, "=abc123")
			},
			scopeToCheck:   ScopePodName,
			expectedResult: false,
		},
		{
			name: "unknown scope name",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopePID, "=1234")
			},
			scopeToCheck:   ScopeName("unknownScope"),
			expectedResult: false,
		},
		{
			name: "invalid scope name",
			setupFilter: func(f *ScopeFilter) error {
				return f.Parse(ScopeContainer, "")
			},
			scopeToCheck:   ScopeName("invalidScopeName"),
			expectedResult: false,
		},
		{
			name: "filter not enabled - no scopes parsed",
			setupFilter: func(f *ScopeFilter) error {
				// Don't parse anything, filter remains disabled
				return nil
			},
			scopeToCheck:   ScopePID,
			expectedResult: false,
		},
		{
			name: "filter not enabled - checking any scope on empty filter",
			setupFilter: func(f *ScopeFilter) error {
				return nil
			},
			scopeToCheck:   ScopeContainer,
			expectedResult: false,
		},
		{
			name: "filter not enabled - checking uid on empty filter",
			setupFilter: func(f *ScopeFilter) error {
				return nil
			},
			scopeToCheck:   ScopeUID,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (comm)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeContainer, ""); err != nil {
					return err
				}
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				return f.Parse(ScopeUID, "=1000")
			},
			scopeToCheck:   ScopeComm,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (syscall)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeHost, ""); err != nil {
					return err
				}
				if err := f.Parse(ScopeTID, "=5678"); err != nil {
					return err
				}
				return f.Parse(ScopeMntNS, "=4026531840")
			},
			scopeToCheck:   ScopeSyscall,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (podName)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeContainer, ""); err != nil {
					return err
				}
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				if err := f.Parse(ScopeUID, "=1000"); err != nil {
					return err
				}
				return f.Parse(ScopeComm, "=bash")
			},
			scopeToCheck:   ScopePodName,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (timestamp)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeContainerID, "=abc123"); err != nil {
					return err
				}
				if err := f.Parse(ScopeContainerImage, "=nginx"); err != nil {
					return err
				}
				return f.Parse(ScopeContainerName, "=my-container")
			},
			scopeToCheck:   ScopeTimestamp,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (hostPpid)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopePID, "=1234"); err != nil {
					return err
				}
				if err := f.Parse(ScopePPID, "=1"); err != nil {
					return err
				}
				return f.Parse(ScopeHostPID, "=5678")
			},
			scopeToCheck:   ScopeHostPPID,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (cgroupId)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopePodName, "=my-pod"); err != nil {
					return err
				}
				if err := f.Parse(ScopePodNamespace, "=default"); err != nil {
					return err
				}
				return f.Parse(ScopePodUID, "=abc-123")
			},
			scopeToCheck:   ScopeCgroupID,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (processorId)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeUID, "=1000"); err != nil {
					return err
				}
				if err := f.Parse(ScopeComm, "=bash"); err != nil {
					return err
				}
				return f.Parse(ScopeHostName, "=myhost")
			},
			scopeToCheck:   ScopeProcessorID,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking non-enabled scope (mntns)",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeContainer, ""); err != nil {
					return err
				}
				if err := f.Parse(ScopePidNS, "=4026531836"); err != nil {
					return err
				}
				return f.Parse(ScopeSyscall, "=openat")
			},
			scopeToCheck:   ScopeMntNS,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking container when only host and pid enabled",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeHost, ""); err != nil {
					return err
				}
				return f.Parse(ScopePID, "=1234")
			},
			scopeToCheck:   ScopeContainer,
			expectedResult: false,
		},
		{
			name: "multiple scopes enabled - checking host when only container and uid enabled",
			setupFilter: func(f *ScopeFilter) error {
				if err := f.Parse(ScopeContainer, ""); err != nil {
					return err
				}
				return f.Parse(ScopeUID, "=1000")
			},
			scopeToCheck:   ScopeHost,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filter := NewScopeFilter()
			err := tt.setupFilter(filter)
			assert.NoError(t, err)

			result := filter.HasScopeFiltering(tt.scopeToCheck)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
