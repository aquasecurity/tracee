package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

type fakeClock struct {
}

func (fakeClock) Now() time.Time {
	return time.Unix(1614045297, 0)
}

type fakeSignature struct {
	types.Signature
}

func (f fakeSignature) GetMetadata() (types.SignatureMetadata, error) {
	return types.SignatureMetadata{
		Name:        "foo bar signature",
		Description: "the most evil",
	}, nil
}

func Test_setupOutput(t *testing.T) {
	var actualOutput bytes.Buffer
	findingCh, err := setupOutput(&actualOutput, fakeClock{}, "")
	require.NoError(t, err)

	findingCh <- types.Finding{
		Data: nil,
		Context: external.Event{
			Timestamp:       12345678,
			ParentProcessID: 1234,
			ProcessID:       5678,
			ProcessName:     "foobar.exe",
			HostName:        "foobar.local",
			EventName:       "ptrace",
			Args: []external.Argument{
				{
					ArgMeta: external.ArgMeta{
						Name: "request",
					},
					Value: "PTRACE_TRACEME",
				},
			},
		},
		Signature: fakeSignature{},
	}
	time.Sleep(time.Millisecond)
	assert.Equal(t, `
*** Detection ***
Time: 1614045297
Signature: foo bar signature
ProcessName: foobar.exe
ProcessID: 5678
ParentProcessID: 1234
Hostname: foobar.local
EventName: ptrace
`, actualOutput.String())
}
