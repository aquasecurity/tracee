package benchmarks

import (
	"io"
	"testing"

	"github.com/aquasecurity/tracee/pkg/cmd/printer"
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
	printerConfigs = []printer.Config{
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
			Name:          "test",
			DefaultAction: "log",
			Rules: []policy.Rule{
				{
					Event: "test",
				},
			},
		},
		{
			Name:          "test2",
			DefaultAction: "log",
			Rules: []policy.Rule{
				{
					Event:  "test",
					Action: []string{"webhook"},
				},
			},
		},
		{
			Name:          "test3",
			DefaultAction: "log",
			Rules: []policy.Rule{
				{
					Event:  "test",
					Action: []string{"webhook"},
				},
			},
		},
		{
			Name:          "test4",
			DefaultAction: "log",
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

	p, err := printer.NewBroadcast(printerConfigs, printer.ContainerModeEnriched)
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

	p, err := printer.NewPolicyEventPrinter(printerConfigs, policies, printer.ContainerModeEnriched)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	for i := 0; i < b.N; i++ {
		p.Print(trace.Event{EventName: "test", MatchedPoliciesNames: []string{"test", "test2"}})
	}
}
