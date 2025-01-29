package ebpf

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	kernelReadFileTypes map[int32]trace.KernelReadType
	onceHashCapsAdd     sync.Once // capabilities for exec hash enabled only once
)

func init() {
	initKernelReadFileTypes() // init kernelReadFileTypes
}

// processEvent processes an event by passing it through all registered event processors.
func (t *Tracee) processEvent(event *trace.Event) []error {
	var errs []error

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
	//
	// Process Tree Processors
	//

	// Processors registered when proctree source "events" is enabled.
	switch t.config.ProcTree.Source {
	case proctree.SourceEvents, proctree.SourceBoth:
		// Event Timestamps Normalization
		//
		// Convert all time relate args to nanoseconds since epoch.
		// NOTE: Make sure to convert time related args (of your event) in here, so that
		// any later code has access to normalized time arguments.
		t.RegisterEventProcessor(events.SchedProcessFork, t.normalizeTimeArg(
			"start_time",
			"parent_start_time",
			"parent_process_start_time",
			"leader_start_time",
		))

		t.RegisterEventProcessor(events.SchedProcessFork, t.procTreeForkProcessor)
		t.RegisterEventProcessor(events.SchedProcessExec, t.procTreeExecProcessor)
		t.RegisterEventProcessor(events.SchedProcessExit, t.procTreeExitProcessor)
	}
	// Processors enriching process tree with regular pipeline events.
	if t.config.ProcTree.Source != proctree.SourceNone {
		t.RegisterEventProcessor(events.All, t.procTreeAddBinInfo)
	}

	//
	// DNS Cache Processors
	//

	if t.config.DNSCacheConfig.Enable {
		// TODO(nadav): Migrate to control plane signals?
		t.RegisterEventProcessor(events.NetPacketDNS, t.populateDnsCache)
	}

	//
	// Regular Pipeline Processors
	//

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
	t.RegisterEventProcessor(events.SharedObjectLoaded, t.processSharedObjectLoaded)
	t.RegisterEventProcessor(events.SuspiciousSyscallSource, t.convertSyscallIDToName)
	t.RegisterEventProcessor(events.StackPivot, t.convertSyscallIDToName)

	//
	// Uprobe based events processors
	//

	// Remove task context
	t.RegisterEventProcessor(events.HiddenKernelModule, t.removeIrrelevantContext)
	t.RegisterEventProcessor(events.HookedSyscall, t.removeIrrelevantContext)
	t.RegisterEventProcessor(events.HookedSeqOps, t.removeIrrelevantContext)
	t.RegisterEventProcessor(events.PrintNetSeqOps, t.removeIrrelevantContext)
	t.RegisterEventProcessor(events.PrintMemDump, t.removeIrrelevantContext)
}

func initKernelReadFileTypes() {
	// TODO: Since we now moved to CORE only - we can probably avoid having all the logic below and
	// simply check for the enum value in bpf code. This will make the event more stable for
	// existing kernels as well as future kernels as well.

	osInfo, err := environment.GetOSInfo()
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

	if kernel593ComparedToRunningKernel == environment.KernelVersionOlder {
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
	} else if kernel570ComparedToRunningKernel == environment.KernelVersionOlder /* Running kernel is newer than 5.7.0 */ &&
		kernel592ComparedToRunningKernel != environment.KernelVersionOlder /* Running kernel is equal or older than 5.9.2*/ &&
		kernel5818ComparedToRunningKernel != environment.KernelVersionEqual /* Running kernel is not 5.8.18 */ {
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
	} else if kernel5818ComparedToRunningKernel == environment.KernelVersionEqual /* Running kernel is 5.8.18 */ ||
		(kernel570ComparedToRunningKernel == environment.KernelVersionNewer && /* Running kernel is older than 5.7.0 */
			kernel4180ComparedToRunningKernel != environment.KernelVersionOlder) /* Running kernel is 4.18 or newer */ {
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
