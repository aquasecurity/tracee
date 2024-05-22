package ebpf

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

const (
	decodeEvts  = 1000
	processEvts = decodeEvts
	deriveEvts  = processEvts / 4
	engineEvts  = processEvts / 4
	sinkEvts    = processEvts + deriveEvts + engineEvts
)

// BenchmarkGetEventFromPool is a benchmark of using a sync.Pool for Event objects,
// which simulates, with caveats, the way the pipeline works.
func BenchmarkGetEventFromPool(b *testing.B) {
	evtPool := sync.Pool{
		New: func() interface{} {
			return &trace.Event{}
		},
	}
	// warm up the pool
	for i := 0; i < decodeEvts; i++ {
		evtPool.Put(evtPool.New())
	}

	eCtx := bufferdecoder.EventContext{}
	containerData := trace.Container{}
	kubernetesData := trace.Kubernetes{}
	eventDefinition := events.Definition{}
	args := []trace.Argument{}
	stackAddresses := []uint64{}
	flags := trace.ContextFlags{}
	syscall := ""
	argnum := uint8(0)

	decodeChan := make(chan *bufferdecoder.EventContext, 10000)
	processChan := make(chan *trace.Event, 10000)
	deriveChan := make(chan *trace.Event)
	engineChan := make(chan *trace.Event)
	sinkChan := make(chan *trace.Event)

	var wg sync.WaitGroup

	b.ResetTimer()

	// decode stage 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < decodeEvts; j++ {
				decodeChan <- &eCtx
			}
		}
	}()

	// decode stage 2
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < decodeEvts; j++ {
				ctx := <-decodeChan
				evt, ok := evtPool.Get().(*trace.Event)
				if !ok {
					b.Error("Failed to get event from pool")
				}
				evt.Timestamp = int(ctx.Ts)
				evt.ThreadStartTime = int(ctx.StartTime)
				evt.ProcessorID = int(ctx.ProcessorId)
				evt.ProcessID = int(ctx.Pid)
				evt.ThreadID = int(ctx.Tid)
				evt.ParentProcessID = int(ctx.Ppid)
				evt.HostProcessID = int(ctx.HostPid)
				evt.HostThreadID = int(ctx.HostTid)
				evt.HostParentProcessID = int(ctx.HostPpid)
				evt.UserID = int(ctx.Uid)
				evt.MountNS = int(ctx.MntID)
				evt.PIDNS = int(ctx.PidID)
				evt.ProcessName = string(bytes.TrimRight(ctx.Comm[:], "\x00"))
				evt.HostName = string(bytes.TrimRight(ctx.UtsName[:], "\x00"))
				evt.CgroupID = uint(ctx.CgroupID)
				evt.ContainerID = containerData.ID
				evt.Container = containerData
				evt.Kubernetes = kubernetesData
				evt.EventID = int(ctx.EventID)
				evt.EventName = eventDefinition.GetName()
				evt.PoliciesVersion = ctx.PoliciesVersion
				evt.MatchedPoliciesKernel = ctx.MatchedPolicies
				evt.MatchedPoliciesUser = 0
				evt.MatchedPolicies = []string{}
				evt.ArgsNum = int(argnum)
				evt.ReturnValue = int(ctx.Retval)
				evt.Args = args
				evt.StackAddresses = stackAddresses
				evt.ContextFlags = flags
				evt.Syscall = syscall
				evt.Metadata = nil
				evt.ThreadEntityId = utils.HashTaskID(ctx.HostTid, ctx.StartTime)
				evt.ProcessEntityId = utils.HashTaskID(ctx.HostPid, ctx.LeaderStartTime)
				evt.ParentEntityId = utils.HashTaskID(ctx.HostPpid, ctx.ParentStartTime)

				processChan <- evt
			}
		}
	}()

	// process stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < processEvts; j++ {
				evt := <-processChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				// get an event from the pool, fill it with data and
				// pass it to the other stages
				evtCopy, ok := evtPool.Get().(*trace.Event)
				if !ok {
					b.Error("Failed to get event from pool")
				}
				*evtCopy = *evt // shallow copy
				sinkChan <- evt
				if j < deriveEvts {
					deriveChan <- evtCopy
				}
				if j < engineEvts {
					engineChan <- evtCopy
				}
			}
		}
	}()

	// derive stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < deriveEvts; j++ {
				evt := <-deriveChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				sinkChan <- evt
			}
		}
	}()

	// engine stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < engineEvts; j++ {
				evt := <-engineChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				sinkChan <- evt
			}
		}
	}()

	// sink stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < sinkEvts; j++ {
				evt := <-sinkChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				_ = evt
				evtPool.Put(evt) // return the event to the pool
			}
		}
	}()

	wg.Wait()
}

// BenchmarkNewEventObject is a benchmark of using a new Event object for each event,
// which simulates, with caveats, the way the pipeline works.
func BenchmarkNewEventObject(b *testing.B) {
	eCtx := bufferdecoder.EventContext{}
	containerData := trace.Container{}
	kubernetesData := trace.Kubernetes{}
	eventDefinition := events.Definition{}
	args := []trace.Argument{}
	stackAddresses := []uint64{}
	flags := trace.ContextFlags{}
	syscall := ""
	argnum := uint8(0)

	decodeChan := make(chan *bufferdecoder.EventContext, 10000)
	processChan := make(chan *trace.Event, 10000)
	deriveChan := make(chan *trace.Event)
	engineChan := make(chan *trace.Event)
	sinkChan := make(chan *trace.Event)

	var wg sync.WaitGroup

	b.ResetTimer()

	// decode stage 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < decodeEvts; j++ {
				decodeChan <- &eCtx
			}
		}
	}()

	// decode stage 2
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < decodeEvts; j++ {
				ctx := <-decodeChan

				evt := trace.Event{
					Timestamp:             int(ctx.Ts),
					ThreadStartTime:       int(ctx.StartTime),
					ProcessorID:           int(ctx.ProcessorId),
					ProcessID:             int(ctx.Pid),
					ThreadID:              int(ctx.Tid),
					ParentProcessID:       int(ctx.Ppid),
					HostProcessID:         int(ctx.HostPid),
					HostThreadID:          int(ctx.HostTid),
					HostParentProcessID:   int(ctx.HostPpid),
					UserID:                int(ctx.Uid),
					MountNS:               int(ctx.MntID),
					PIDNS:                 int(ctx.PidID),
					ProcessName:           string(bytes.TrimRight(ctx.Comm[:], "\x00")),
					HostName:              string(bytes.TrimRight(ctx.UtsName[:], "\x00")),
					CgroupID:              uint(ctx.CgroupID),
					ContainerID:           containerData.ID,
					Container:             containerData,
					Kubernetes:            kubernetesData,
					EventID:               int(ctx.EventID),
					EventName:             eventDefinition.GetName(),
					PoliciesVersion:       ctx.PoliciesVersion,
					MatchedPoliciesKernel: ctx.MatchedPolicies,
					ArgsNum:               int(argnum),
					ReturnValue:           int(ctx.Retval),
					Args:                  args,
					StackAddresses:        stackAddresses,
					ContextFlags:          flags,
					Syscall:               syscall,
					ThreadEntityId:        utils.HashTaskID(ctx.HostTid, ctx.StartTime),
					ProcessEntityId:       utils.HashTaskID(ctx.HostPid, ctx.LeaderStartTime),
					ParentEntityId:        utils.HashTaskID(ctx.HostPpid, ctx.ParentStartTime),
				}

				processChan <- &evt
			}
		}
	}()

	// process stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < processEvts; j++ {
				evt := <-processChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				evtCopy := *evt
				sinkChan <- evt
				if j < deriveEvts {
					deriveChan <- &evtCopy
				}
				if j < engineEvts {
					engineChan <- &evtCopy
				}
			}
		}
	}()

	// derive stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < deriveEvts; j++ {
				evt := <-deriveChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				sinkChan <- evt
			}
		}
	}()

	// engine stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < engineEvts; j++ {
				evt := <-engineChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				sinkChan <- evt
			}
		}
	}()

	// sink stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			for j := 0; j < sinkEvts; j++ {
				evt := <-sinkChan
				// simulate some work through the pipeline
				time.Sleep(1 * time.Millisecond)

				_ = evt
				evt = nil // release the reference to the event
			}
		}
	}()

	wg.Wait()
}
