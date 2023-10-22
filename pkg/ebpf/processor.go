package ebpf

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	kernelReadFileTypes map[int32]trace.KernelReadType
	onceExecHash        sync.Once // capabilities for exec hash enabled only once
)

func init() {
	initKernelReadFileTypes() // init kernelReadFileTypes
}

// processEvent processes an event by passing it through all registered event processors.
func (t *Tracee) processEvent(event *trace.Event) []error {
	errs := []error{}

	processors := t.eventProcessor[events.ID(event.EventID)]         // this event processors
	processors = append(processors, t.eventProcessor[events.All]...) // all events processors

	for _, processor := range processors {
		err := processor(event)
		if err != nil {
			logger.Errorw("Error processing event", "event", event.EventName, "error", err)
			errs = append(errs, err)
		}
	}

	return errs
}

// processLost handles lost events in a separate goroutine.
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

// RegisterEventProcessor registers a new event processor for a specific event id.
func (t *Tracee) RegisterEventProcessor(id events.ID, proc func(evt *trace.Event) error) {
	if t.eventProcessor == nil {
		t.eventProcessor = make(map[events.ID][]func(evt *trace.Event) error)
	}
	if t.eventProcessor[id] == nil {
		t.eventProcessor[id] = make([]func(evt *trace.Event) error, 0)
	}
	t.eventProcessor[id] = append(t.eventProcessor[id], proc)
}

// registerEventProcessors registers all event processors, each to a specific event id.
func (t *Tracee) registerEventProcessors() {
	// Process events for the process tree before the regular event processing.
	// NOTE: Use the switch case below to register your processor.
	switch t.config.ProcTree.Source {
	case proctree.SourceNone: // break (proctree is disabled)
	case proctree.SourceSignals: // break (processors registered in control plane)
	case proctree.SourceBoth:
		fallthrough
	case proctree.SourceEvents: // Register processors for when proctree source is "events"
		t.RegisterEventProcessor(events.SchedProcessFork, t.procTreeForkProcessor)
		t.RegisterEventProcessor(events.SchedProcessExec, t.procTreeExecProcessor)
		t.RegisterEventProcessor(events.SchedProcessExit, t.procTreeExitProcessor)
		fallthrough
	default: // Register processors for whenever proc tree is enabled
		t.RegisterEventProcessor(events.All, t.procTreeAddBinInfo)
	}
	// Processors related to proctree that runs even when proctree is disabled
	t.RegisterEventProcessor(events.SchedProcessFork, t.procTreeForkRemoveArgs)

	// Process events from the regular pipeline.
	// NOTE: Your processor goes very likely here.
	t.RegisterEventProcessor(events.VfsWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.VfsWritev, t.processWriteEvent)
	t.RegisterEventProcessor(events.KernelWrite, t.processWriteEvent)
	t.RegisterEventProcessor(events.SecurityKernelReadFile, processKernelReadFile)
	t.RegisterEventProcessor(events.SecurityPostReadFile, processKernelReadFile)
	t.RegisterEventProcessor(events.SchedProcessExec, t.processSchedProcessExec)
	t.RegisterEventProcessor(events.DoInitModule, t.processDoInitModule)
	t.RegisterEventProcessor(events.HookedProcFops, t.processHookedProcFops)
	t.RegisterEventProcessor(events.PrintNetSeqOps, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.PrintMemDump, t.processTriggeredEvent)
	t.RegisterEventProcessor(events.PrintMemDump, t.processPrintMemDump)

	// Convert all time relate args to nanoseconds since epoch.
	// NOTE: Make sure to convert time related args (of your event) in here.
	t.RegisterEventProcessor(events.SchedProcessFork, t.processSchedProcessFork)
	t.RegisterEventProcessor(events.All, t.normalizeEventCtxTimes)
}

func initKernelReadFileTypes() {
	// TODO: Since we now moved to CORE only - we can probably avoid having all the logic below and
	// simply check for the enum value in bpf code. This will make the event more stable for
	// existing kernels as well as future kernels as well.

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
