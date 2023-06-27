package benchmarks

import (
	"io"
	"testing"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/types/trace"
)

type writerCloser struct {
	io.Writer
}

func (wc writerCloser) Close() error {
	// Noop
	return nil
}

var (
	printerConfigs = []config.PrinterConfig{
		{
			Kind:    "json",
			OutPath: "stdout",
			OutFile: writerCloser{io.Discard},
		},
		{
			Kind:    "webhook",
			OutPath: "http://localhost:8080",
			OutFile: writerCloser{io.Discard},
		},
	}

	policies = []policy.PolicyFile{
		{
			Name:           "test",
			DefaultActions: []string{"log"},
			Rules: []policy.Rule{
				{
					Event: "test",
				},
			},
		},
		{
			Name:           "test2",
			DefaultActions: []string{"log"},
			Rules: []policy.Rule{
				{
					Event:   "test",
					Actions: []string{"webhook"},
				},
			},
		},
		{
			Name:           "test3",
			DefaultActions: []string{"log"},
			Rules: []policy.Rule{
				{
					Event:   "test",
					Actions: []string{"webhook"},
				},
			},
		},
		{
			Name:           "test4",
			DefaultActions: []string{"log"},
			Rules: []policy.Rule{
				{
					Event: "test",
				},
			},
		},
	}
)

func BenchmarkBroadcastPrinter(b *testing.B) {
	b.ReportAllocs()

	p, err := printer.NewBroadcast(printerConfigs, config.ContainerModeEnriched)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	for i := 0; i < b.N; i++ {
		p.Print(trace.Event{EventName: "test"})
	}
}

func BenchmarkPolicyPrinter(b *testing.B) {
	b.ReportAllocs()

	p, err := printer.NewPolicyEventPrinter(printerConfigs, policies, config.ContainerModeEnriched)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	for i := 0; i < b.N; i++ {
		p.Print(trace.Event{EventName: "test", MatchedPolicies: []string{"test", "test2"}})
	}
}
