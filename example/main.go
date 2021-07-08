package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/rego"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/simar7/libtracee"
)

const (
	inputEventsCount = 100
)

func main() {
	eventsProcessed, outputChan, err := libtracee.SetupTracee(libtracee.AddNSigs([]func() (types.Signature, error){
		golang.NewCodeInjectionSignature,
		rego.NewCodeInjectionSignature,
		//wasm.NewCodeInjectionSignature,
	}), inputEventsCount, getBPFObjectPath())
	if err != nil {
		log.Fatal("unable to initialize Tracee: ", err)
	}

	// show all findings
	go func(outputChan chan types.Finding) {
		showFindings(outputChan)
	}(outputChan)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	fmt.Println("waiting for interrupt to finish...")
	<-sig
	fmt.Println("total events processed: ", *eventsProcessed)
}

func showFindings(outputChan chan types.Finding) {
	for {
		select {
		case finding := <-outputChan:
			fmt.Println(finding)
		}
	}
}

func getBPFObjectPath() string {
	return "/home/vagrant/repos/tracee/tracee-ebpf/dist/tracee.bpf.5_8_0-55-generic.v0_5_4-18-g31f21b8.o" // TODO: Export getBPFObject() in Tracee
}
