package benchmark

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/rego"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/wasm"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/simar7/libtracee"
)

const (
	inputEventsCount = 10000
)

type bench struct {
	name    string
	numSigs []int
	sigFunc func() (types.Signature, error)
}

func BenchmarkTracee(b *testing.B) {
	benches := []bench{
		{
			name:    "golang sigs only",
			numSigs: []int{1, 2, 4, 8},
			sigFunc: golang.NewCodeInjectionSignature,
		},
		{
			name:    "rego sigs only",
			numSigs: []int{1, 2, 4},
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:    "wasm sigs only",
			numSigs: []int{1, 2},
			sigFunc: wasm.NewCodeInjectionSignature,
		},
	}

	for _, bc := range benches {
		bc := bc
		for _, numSigs := range bc.numSigs {
			for i := 0; i < b.N; i++ {
				b.Run(fmt.Sprintf("%s/%dsigs", bc.name, numSigs), func(b *testing.B) {
					b.ReportAllocs()
					b.StopTimer()
					var ss []func() (types.Signature, error)
					for i := 0; i < numSigs; i++ {
						ss = append(ss, bc.sigFunc)
					}
					totalEvents, tmpDir := libtracee.SetupTracee(libtracee.AddNSigs(ss), inputEventsCount)
					defer func() {
						_ = os.RemoveAll(tmpDir)
					}()
					b.StartTimer()

					sig := make(chan os.Signal, 1)
					signal.Notify(sig, os.Interrupt)
					go func() {
						generateAndStop(totalEvents, sig)
					}()

					fmt.Println("waiting for interrupt to finish...")
					<-sig
					fmt.Println("total events: ", *totalEvents)
				})
			}
		}
	}
}

func generateAndStop(totalEvents *int, sig chan os.Signal) {
	for {
		if *totalEvents >= inputEventsCount {
			sig <- os.Interrupt
		} else {
			_ = exec.Command("ls").Run()
		}
	}
}
