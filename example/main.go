package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/simar7/libtracee"
)

const (
	inputEventsCount = 10000
)

func main() {
	totalEvents, tmpDir := libtracee.SetupTracee(libtracee.AddNSigs([]func() (types.Signature, error){
		golang.NewCodeInjectionSignature,
		//rego.NewCodeInjectionSignature,
		//wasm.NewCodeInjectionSignature,
	}), inputEventsCount)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	fmt.Println("waiting for interrupt to finish...")
	<-sig
	fmt.Println("total events: ", *totalEvents)
}
