package ebpf

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	// initializing kernelReadFileTypes once at init.
	kernelReadFileTypes map[int32]trace.KernelReadType
	// exec hash might add capabilities to base ring
	onceExecHash sync.Once
)

func init() {
	initKernelReadFileTypes()
}

func (t *Tracee) processLostEvents() {
	logger.Debugw("Starting processLostEvents goroutine")
	defer logger.Debugw("Stopped processLostEvents goroutine")

	// Since this is an end-stage goroutine, it should be terminated when:
	// - lostEvChannel is closed, or finally when;
	// - internal done channel is closed (not ctx).
	for {
		select {
		case lost, ok := <-t.lostEvChannel:
			if !ok {
				return // lostEvChannel is closed, lost is zero value
			}

			if err := t.stats.LostEvCount.Increment(lost); err != nil {
				logger.Errorw("Incrementing lost event count", "error", err)
			}
			logger.Warnw(fmt.Sprintf("Lost %d events", lost))

		// internal done channel is closed when Tracee is stopped via Tracee.Close()
		case <-t.done:
			return
		}
	}
}

const (
	IterateShared int = iota
	Iterate
)

func (t *Tracee) processEvent(event *trace.Event) []error {
	eventId := events.ID(event.EventID)
	processors := t.eventProcessor[eventId]
	errs := []error{}
	for _, procFunc := range processors {
		err := procFunc(event)
		if err != nil {
			logger.Errorw("Error processing event", "event", event.EventName, "error", err)
			errs = append(errs, err)
		}
	}
	return errs
}

const (
	EventProcessor int = iota
	ProcTreeProcessor
)

// RegisterProcessor registers a pipeline processing handler for an event.
func (t *Tracee) RegisterProcessor(
	processorType int, id events.ID, proc func(evt *trace.Event) error,
) {
	switch processorType {
	case EventProcessor:
		if t.eventProcessor[id] == nil {
			t.eventProcessor[id] = make([]func(evt *trace.Event) error, 0)
		}
		t.eventProcessor[id] = append(t.eventProcessor[id], proc)
	case ProcTreeProcessor:
		if t.procTreeProcessor[id] == nil {
			t.procTreeProcessor[id] = make([]func(evt *trace.Event) error, 0)
		}
		t.procTreeProcessor[id] = append(t.procTreeProcessor[id], proc)
	}
}

// registerEventProcessors registers tracee's internal default event processors
func (t *Tracee) registerEventProcessors() error {
	if t.eventProcessor == nil {
		return errfmt.Errorf("tracee not initialized yet")
	}

	if t.eventProcessor == nil {
		t.eventProcessor = make(map[events.ID][]func(evt *trace.Event) error)
	}

	t.RegisterProcessor(EventProcessor, events.VfsWrite, t.processWriteEvent)
	t.RegisterProcessor(EventProcessor, events.VfsWritev, t.processWriteEvent)
	t.RegisterProcessor(EventProcessor, events.KernelWrite, t.processWriteEvent)
	t.RegisterProcessor(EventProcessor, events.SchedProcessExec, t.processSchedProcessExec)
	t.RegisterProcessor(EventProcessor, events.SchedProcessFork, t.processSchedProcessFork)
	t.RegisterProcessor(EventProcessor, events.DoInitModule, t.processDoInitModule)
	t.RegisterProcessor(EventProcessor, events.HookedProcFops, t.processHookedProcFops)
	t.RegisterProcessor(EventProcessor, events.SecurityKernelReadFile, processKernelReadFile)
	t.RegisterProcessor(EventProcessor, events.SecurityPostReadFile, processKernelReadFile)
	t.RegisterProcessor(EventProcessor, events.PrintNetSeqOps, t.processTriggeredEvent)
	t.RegisterProcessor(EventProcessor, events.PrintSyscallTable, t.processTriggeredEvent)
	t.RegisterProcessor(EventProcessor, events.PrintMemDump, t.processTriggeredEvent)
	t.RegisterProcessor(EventProcessor, events.PrintMemDump, t.processPrintMemDump)

	return nil
}

func (t *Tracee) registerProcTreeProcessors() error {
	if t.procTreeProcessor == nil {
		return errfmt.Errorf("tracee not initialized yet")
	}

	if t.procTreeProcessor == nil {
		t.procTreeProcessor = make(map[events.ID][]func(evt *trace.Event) error)
	}

	t.RegisterProcessor(ProcTreeProcessor, events.Setuid, t.processProcTreeSetuid)

	return nil
}

func initKernelReadFileTypes() {
	osInfo, err := helpers.GetOSInfo()
	if err != nil {
		return
	}

	kernel593ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.3")
	if err != nil {
		return
	}
	kernel570ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.7.0")
	if err != nil {
		return
	}
	kernel592ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.9.2")
	if err != nil {
		return
	}
	kernel5818ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("5.8.18")
	if err != nil {
		return
	}
	kernel4180ComparedToRunningKernel, err := osInfo.CompareOSBaseKernelRelease("4.18.0")
	if err != nil {
		return
	}

	if kernel593ComparedToRunningKernel == helpers.KernelVersionOlder {
		// running kernel version: >=5.9.3
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadKernelModule,
			3: trace.KernelReadKExecImage,
			4: trace.KernelReadKExecInitRAMFS,
			5: trace.KernelReadSecurityPolicy,
			6: trace.KernelReadx509Certificate,
		}
	} else if kernel570ComparedToRunningKernel == helpers.KernelVersionOlder /* Running kernel is newer than 5.7.0 */ &&
		kernel592ComparedToRunningKernel != helpers.KernelVersionOlder /* Running kernel is equal or older than 5.9.2*/ &&
		kernel5818ComparedToRunningKernel != helpers.KernelVersionEqual /* Running kernel is not 5.8.18 */ {
		// running kernel version: >=5.7 && <=5.9.2 && !=5.8.18
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadFirmware,
			3: trace.KernelReadFirmware,
			4: trace.KernelReadKernelModule,
			5: trace.KernelReadKExecImage,
			6: trace.KernelReadKExecInitRAMFS,
			7: trace.KernelReadSecurityPolicy,
			8: trace.KernelReadx509Certificate,
		}
	} else if kernel5818ComparedToRunningKernel == helpers.KernelVersionEqual /* Running kernel is 5.8.18 */ ||
		(kernel570ComparedToRunningKernel == helpers.KernelVersionNewer && /* Running kernel is older than 5.7.0 */
			kernel4180ComparedToRunningKernel != helpers.KernelVersionOlder) /* Running kernel is 4.18 or newer */ {
		// running kernel version: ==5.8.18 || (<5.7 && >=4.18)
		kernelReadFileTypes = map[int32]trace.KernelReadType{
			0: trace.KernelReadUnknown,
			1: trace.KernelReadFirmware,
			2: trace.KernelReadFirmware,
			3: trace.KernelReadKernelModule,
			4: trace.KernelReadKExecImage,
			5: trace.KernelReadKExecInitRAMFS,
			6: trace.KernelReadSecurityPolicy,
			7: trace.KernelReadx509Certificate,
		}
	}
}
