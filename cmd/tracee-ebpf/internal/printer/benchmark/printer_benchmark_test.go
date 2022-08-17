package printer_benchmark_test

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/internal/printer"
	"github.com/aquasecurity/tracee/pkg/proto"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/require"
	protoenc "google.golang.org/protobuf/proto"
)

var (
	benchmarkEvents []trace.Event
)

func init() {
	eventFile, err := os.Open("event_dump.gob")
	if err != nil {
		panic(err)
	}

	dec := gob.NewDecoder(eventFile)
	gob.Register(trace.Event{})
	gob.Register(trace.SlimCred{})
	gob.Register(make(map[string]string))
	gob.Register(trace.PktMeta{})
	gob.Register([]trace.HookedSymbolData{})
	gob.Register(map[string]trace.HookedSymbolData{})
	gob.Register([]trace.DnsQueryData{})
	gob.Register([]trace.DnsResponseData{})
	for {
		var event trace.Event
		err := dec.Decode(&event)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic(fmt.Sprintf("error while decoding event (gob): %v\n", err))
			}
		} else {
			benchmarkEvents = append(benchmarkEvents, event)
		}
	}
}

func Benchmark_JsonPrinter(b *testing.B) {
	devNull, err := os.OpenFile("/dev/null", os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(b, err)
	defer devNull.Close()

	printer, err := printer.New(printer.Config{
		Kind:    "json",
		OutFile: devNull,
		ErrFile: devNull,
	})
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, evt := range benchmarkEvents {
			printer.Print(evt)
		}
	}
}

func Benchmark_GobPrinter(b *testing.B) {
	devNull, err := os.OpenFile("/dev/null", os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(b, err)
	defer devNull.Close()

	printer, err := printer.New(printer.Config{
		Kind:    "gob",
		OutFile: devNull,
		ErrFile: devNull,
	})
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, evt := range benchmarkEvents {
			printer.Print(evt)
		}
	}
}

func Benchmark_ProtobufPrinter(b *testing.B) {
	devNull, err := os.OpenFile("/dev/null", os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(b, err)
	defer devNull.Close()

	printer, err := printer.New(printer.Config{
		Kind:    "protobuf",
		OutFile: devNull,
		ErrFile: devNull,
	})
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, evt := range benchmarkEvents {
			printer.Print(evt)
		}
	}
}

func Benchmark_JsonMarshal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, evt := range benchmarkEvents {
			json.Marshal(evt)
		}
	}
}

// benchmarking for gob is redundant since encoding includes printing
// and marshaling.

func Benchmark_ProtobufMarshal(b *testing.B) {
	readyToMarshal := []*proto.Event{}
	for _, evt := range benchmarkEvents {
		wrap, _ := proto.Wrap(evt)
		readyToMarshal = append(readyToMarshal, wrap)
	}
	encoder := base64.StdEncoding

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, evt := range readyToMarshal {
			b, _ := protoenc.Marshal(evt)
			encoder.EncodeToString(b)
		}
	}
}

func BenchmarkWrap(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, evt := range benchmarkEvents {
			proto.Wrap(evt)
		}
	}
}
