```go
// initializing
import bpf "github.com/aquasecurity/tracee/libbpfgo"
...
bpfModule := bpf.NewModuleFromFile(bpfObjectPath)
bpfModule.BPFLoadObject()

// maps
mymap, _ := bpfModule.GetMap("mymap")
mymap.Update(key, value)

// perf buffer
pb, _ := bpfModule.InitPerfBuf("events", eventsChannel, lostEvChannel, buffSize)
pb.Start()
e := <-eventsChannel
```

There are many more methods supported and functionality available. We will be documenting this library more extensively in the future, but in the meantime, you can take a look at the `libbpf_wrapper.go` code to get an idea of what's possible, or look at the [Tracee code](https://github.com/aquasecurity/tracee/blob/main/tracee-ebpf/tracee/tracee.go) as a consumer of this library, or just ask us by creating [a new discussion](https://github.com/aquasecurity/tracee/discussions) and we'd love to help.
