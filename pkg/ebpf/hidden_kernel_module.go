package ebpf

import (
	gocontext "context"
	"time"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

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
// Several techniques are used to find hidden modules - each of them is triggered by
// using a tailcall.
func (t *Tracee) lkmSeekerRoutine(ctx gocontext.Context) {
	logger.Debugw("Starting lkmSeekerRoutine goroutine")
	defer logger.Debugw("Stopped lkmSeekerRoutine goroutine")

	if t.eventsState[events.HiddenKernelModule].Emit == 0 {
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

	err = derive.InitHiddenKernelModules(modsMap, newModMap, deletedModMap)
	if err != nil {
		return
	}

	wakeupChan := derive.GetWakeupChannelRead()

	run := true // Marks when the lkm hiding whole seeking logic should run.

	for {
		if run {
			// Update eBPF maps for kernel logic
			err = derive.FillModulesFromProcFs()
			if err != nil {
				logger.Errorw("Hidden kernel module seeker stopped!: " + err.Error())
				return
			}

			// Run kernel logic
			t.triggerKernelModuleSeeker()

			// Clear eBPF maps
			err := derive.ClearModulesState()
			if err != nil {
				logger.Errorw("Hidden kernel module seeker stopped!: failed clearing maps. " + err.Error())
				return
			}

			run = false
		} else {
			select {
			case <-ctx.Done():
				return

			case <-time.After(utils.GenerateRandomDuration(10, 300)):
				run = true // Run from time to time.

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
