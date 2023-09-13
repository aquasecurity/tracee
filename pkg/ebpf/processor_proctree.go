package ebpf

import (
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

func (t *Tracee) processProcTreeSetuid(event *trace.Event) error {

	hash := event.EntityID

	if event.ProcessID != event.ThreadID {
		// task is a thread

		thread, ok := t.processTree.GetOrCreateThreadByHashOkay(hash)
		if !ok {
			// a thread was created, try to populate it
			thread.GetInfo().SetFeedAt(
				proctree.TaskInfoFeed{
					Name:        event.ProcessName,
					Tid:         int(event.ThreadID),
					Pid:         int(event.ProcessID),
					NsTid:       int(event.ThreadID),
					NsPid:       int(event.ProcessID),
					Uid:         event.UserID,
					Gid:         -1, // do not change the GID
					StartTimeNS: uint64(event.ThreadStartTime),
				},

				utils.NsSinceBootTimeToTime(uint64(event.Timestamp)),
			)
			// try to enrich from procfs asynchronously (instead of reading procfs continuously)
			t.processTree.FeedFromProcFSAsync(event.ProcessID)
		}

		// processHash := thread.GetLeaderHash()
	}

	// task is a real process

	// process := t.processTree.GetOrCreateProcessByHash(hash)

	return nil
}
