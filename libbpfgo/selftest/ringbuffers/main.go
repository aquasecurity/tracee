package main

import "C"

import (
	bpf "github.com/aquasecurity/tracee/libbpfgo"
	"os"
	"fmt"
	"encoding/binary"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("self.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_mmap")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	numberOfEventsReceived := 0

recvLoop:
	for  {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	rb.Stop()
	rb.Stop()
	rb.Close()
	rb.Close()
	rb.Stop()
}
