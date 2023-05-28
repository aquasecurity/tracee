package ebpf

import (
	gocontext "context"
	"math/rand"
	"time"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/logger"
)

const throttleSecs = 2 // Seconds

// lkmSeekerRoutine handles the kernel module hiding check logic. The logic runs
// periodically, unless getting interrupted by a message in the channel.
//
// Currently, there are 2 types of messages:
//
//  1. A new kernel module was loaded, trigger a check for hidden kernel
//     modules.
//
//  2. Found hidden module by new mod logic (check newModsCheckForHidden for
//     more info), submit it back to eBPF, which will return it to userspace,
//     this time making it get submitted as an event to the user.
//
// Since each module insert will cause the logic to run, we want to avoid
// exhausting the system (say someone loads modules in a loop). To address that,
// there's a cool-down period which must pass for the scan to rerun. Several
// techniques is used to find hidden modules - each of them is triggered by
// using a tailcall.
func (t *Tracee) lkmSeekerRoutine(ctx gocontext.Context) {
	logger.Debugw("Starting lkmSeekerRoutine goroutine")
	defer logger.Debugw("Stopped lkmSeekerRoutine goroutine")

	if t.events[events.HiddenKernelModule].emit == 0 {
		return
	}

	modsMap, err := t.bpfModule.GetMap("modules_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	newModMap, err := t.bpfModule.GetMap("new_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	deletedModMap, err := t.bpfModule.GetMap("recent_deleted_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	insertedModMap, err := t.bpfModule.GetMap("recent_inserted_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	err = derive.InitHiddenKernelModules(modsMap, newModMap, deletedModMap, insertedModMap)
	if err != nil {
		return
	}

	wakeupChan := derive.GetWakeupChannelRead()

	// generateRandomDuration returns a random duration between min and max, inclusive
	generateRandomDuration := func(min, max int) time.Duration {
		randDuration := time.Duration(rand.Intn(max-min+1)+min) * time.Second
		return randDuration
	}

	// Since on each module load the scan is triggered, the following variables
	// are used to enforce that we scan at most once in minSleepBetweenRuns
	// seconds, to avoid exhausting the system

	lastTriggerTime := time.Now()
	var throttleTimer <-chan time.Time

	run := true // marks when the lkm hiding whole seeking logic should run.

	for {
		if run {
			if throttleTimer != nil {
				run = false
				continue // A run is scheduled in the future, so don't run yet
			}

			// Throttling Timer: Do not execute before minSleepBetweenRuns!
			// (safe-guard against exhausting the system)

			if lastTriggerTime.Add(throttleSecs * time.Second).After(time.Now()) {
				throttleTimer = time.After(
					time.Until(
						lastTriggerTime.Add(throttleSecs * time.Second),
					),
				)
				run = false
				continue
			}

			// update eBPF maps for kernel logic
			err = derive.FillModulesFromProcFs(t.kernelSymbols)
			if err != nil {
				logger.Errorw("Hidden kernel module seeker stopped!: " + err.Error())
				return
			}

			// prepare throttle timer
			lastTriggerTime = time.Now()

			// run kernel logic
			t.triggerKernelModuleSeeker()

			// clear eBPF maps
			derive.ClearModulesState()
		} else {
			select {
			case <-ctx.Done():
				return

			case <-time.After(generateRandomDuration(10, 300)):
				run = true // run from time to time.

			case <-throttleTimer:
				throttleTimer = nil // cool-down period ended...
				run = true          // ...run now!

			case scanReq := <-wakeupChan:
				if scanReq.Flags&derive.FullScan != 0 {
					run = true
				} else if scanReq.Flags&derive.NewMod != 0 {
					run = false
					t.triggerKernelModuleSubmitter(scanReq.Address, uint64(scanReq.Flags))
				} else {
					logger.Errorw("lkm_seeker: unexpected flags", "flags", scanReq.Flags)
				}
			}
		}
	}
}

//go:noinline
func (t *Tracee) triggerKernelModuleSeeker() {
}

//go:noinline
func (t *Tracee) triggerKernelModuleSubmitter(address uint64, flags uint64) {
}
