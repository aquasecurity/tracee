package replay

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

// The replay producer parses files with protojson, while tracee's json output
// writes events with the custom high-performance Event.MarshalJSON. These
// tests guard that contract: whatever tracee writes, replay must read back.

// writeEventsFile marshals the given events with Event.MarshalJSON (exactly
// what tracee --output json does) into a JSON Lines temp file.
func writeEventsFile(t *testing.T, events []*v1beta1.Event) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "events.json")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	for _, e := range events {
		line, err := e.MarshalJSON()
		require.NoError(t, err)
		_, err = f.Write(append(line, '\n'))
		require.NoError(t, err)
	}
	return path
}

// produceFromFile runs the producer on the given file and collects the events
// it parsed, along with any terminal scan error.
func produceFromFile(t *testing.T, path string) ([]*v1beta1.Event, error) {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	eventChan := make(chan *v1beta1.Event, eventChanBufferSize)
	scanErr := make(chan error, 1)
	go produce(context.Background(), f, eventChan, scanErr)

	collected := []*v1beta1.Event{}
	for e := range eventChan {
		collected = append(collected, e)
	}
	select {
	case err := <-scanErr:
		return collected, err
	default:
		return collected, nil
	}
}

func TestProduce_RoundTripFromTraceeJSONOutput(t *testing.T) {
	original := &v1beta1.Event{
		Timestamp: timestamppb.Now(),
		Id:        v1beta1.EventId_execve,
		Name:      "execve",
		Policies: &v1beta1.Policies{
			Matched: []string{"policy1"},
		},
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Executable: &v1beta1.Executable{Path: "/bin/bash"},
				HostPid:    wrapperspb.UInt32(1234),
				Pid:        wrapperspb.UInt32(4321),
			},
		},
		Data: []*v1beta1.EventValue{
			{Name: "pathname", Value: &v1beta1.EventValue_Str{Str: "/bin/ls"}},
			{Name: "argc", Value: &v1beta1.EventValue_Int32{Int32: 2}},
			{Name: "some_flag", Value: &v1beta1.EventValue_Bool{Bool: true}},
			{Name: "inode", Value: &v1beta1.EventValue_UInt64{UInt64: 987654321}},
		},
	}

	path := writeEventsFile(t, []*v1beta1.Event{original})
	collected, err := produceFromFile(t, path)
	require.NoError(t, err)
	require.Len(t, collected, 1, "producer should parse the event written by tracee's json output")

	parsed := collected[0]
	assert.Equal(t, original.Id, parsed.Id)
	assert.Equal(t, original.Name, parsed.Name)
	assert.Equal(t, original.Timestamp.AsTime(), parsed.Timestamp.AsTime())
	assert.Equal(t, original.Policies.GetMatched(), parsed.Policies.GetMatched())
	assert.Equal(t, "/bin/bash", parsed.GetWorkload().GetProcess().GetExecutable().GetPath())
	assert.Equal(t, uint32(1234), parsed.GetWorkload().GetProcess().GetHostPid().GetValue())
	assert.Equal(t, uint32(4321), parsed.GetWorkload().GetProcess().GetPid().GetValue())

	pathname, found := v1beta1.GetData[string](parsed, "pathname")
	require.True(t, found, "string data value must survive the roundtrip")
	assert.Equal(t, "/bin/ls", pathname)

	argc, found := v1beta1.GetData[int32](parsed, "argc")
	require.True(t, found, "int32 data value must survive the roundtrip")
	assert.Equal(t, int32(2), argc)

	someFlag, found := v1beta1.GetData[bool](parsed, "some_flag")
	require.True(t, found, "bool data value must survive the roundtrip")
	assert.True(t, someFlag)

	inode, found := v1beta1.GetData[uint64](parsed, "inode")
	require.True(t, found, "uint64 data value must survive the roundtrip")
	assert.Equal(t, uint64(987654321), inode)
}

func TestProduce_LongLines(t *testing.T) {
	// Real tracee events can exceed bufio.Scanner's 64KB default line limit
	// (argument data, environment variables, stack traces)
	bigValue := strings.Repeat("A", 128*1024)
	events := []*v1beta1.Event{
		{
			Timestamp: timestamppb.Now(),
			Id:        v1beta1.EventId_execve,
			Name:      "execve",
			Data: []*v1beta1.EventValue{
				{Name: "env", Value: &v1beta1.EventValue_Str{Str: bigValue}},
			},
		},
		{
			Timestamp: timestamppb.Now(),
			Id:        v1beta1.EventId_openat,
			Name:      "openat",
		},
	}

	collected, err := produceFromFile(t, writeEventsFile(t, events))
	require.NoError(t, err)
	require.Len(t, collected, 2, "a >64KB line must not abort the replay")

	env, found := v1beta1.GetData[string](collected[0], "env")
	require.True(t, found)
	assert.Equal(t, bigValue, env)
	assert.Equal(t, "openat", collected[1].Name)
}

func TestProduce_SkipsMalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	content := `{"id":60,"name":"execve"}
not json at all
{"id":258,"name":"openat"}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	collected, err := produceFromFile(t, path)
	require.NoError(t, err)
	require.Len(t, collected, 2, "malformed lines are skipped, valid ones kept")
	assert.Equal(t, "execve", collected[0].Name)
	assert.Equal(t, "openat", collected[1].Name)
}

func TestProduce_OversizedLineIsTerminalError(t *testing.T) {
	// A line beyond scannerMaxLineSize permanently stops bufio.Scanner: the
	// rest of the file is unreadable, so the producer must surface the error
	// instead of masquerading as a clean EOF
	path := filepath.Join(t.TempDir(), "events.json")
	f, err := os.Create(path)
	require.NoError(t, err)
	_, err = f.WriteString(`{"id":60,"name":"execve"}` + "\n")
	require.NoError(t, err)
	_, err = f.WriteString(`{"id":60,"name":"` + strings.Repeat("A", scannerMaxLineSize) + `"}` + "\n")
	require.NoError(t, err)
	_, err = f.WriteString(`{"id":258,"name":"openat"}` + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	collected, scanErr := produceFromFile(t, path)
	require.Error(t, scanErr, "oversized line must be reported as a scan error")
	assert.Contains(t, scanErr.Error(), "token too long")
	assert.Len(t, collected, 1, "only events before the oversized line are readable")
}
