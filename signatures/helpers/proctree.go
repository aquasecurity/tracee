package helpers

import (
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessTreeDS is an envelope to the process tree datasource API, to make it intuitive and easy
// to use.
type ProcessTreeDS struct {
	ds detect.DataSource
}

// InitProcessTreeDS init a datasource envelopment instance with the process tree datasource.
func InitProcessTreeDS(ds detect.DataSource) *ProcessTreeDS {
	return &ProcessTreeDS{ds: ds}
}

// GetProcessTreeDataSource init a datasource envelopment instance using the context all signatures
// are initialized with.
// This is the recommended way to initialize an instance, as it simpler to use.
func GetProcessTreeDataSource(ctx detect.SignatureContext) (*ProcessTreeDS, error) {
	processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
	if !ok {
		return nil, fmt.Errorf("data source tracee/process_tree is not registered")
	}

	if processTreeDataSource.Version() > 1 {
		return nil, fmt.Errorf(
			"data source tracee/process_tree version %d is not supported",
			processTreeDataSource.Version(),
		)
	}

	return InitProcessTreeDS(processTreeDataSource), nil
}

// GetThreadInfo query the datasource for the information of a specific thread.
func (ptds *ProcessTreeDS) GetThreadInfo(threadKey datasource.ThreadKey) (
	*datasource.TimeRelevantInfo[datasource.ThreadInfo], error,
) {
	threadQueryAnswer, err := ptds.ds.Get(threadKey)
	if err != nil {
		return nil, fmt.Errorf("could not find thread for thread %d", threadKey.EntityId)
	}
	threadInfo, ok := threadQueryAnswer["thread_info"].(datasource.TimeRelevantInfo[datasource.ThreadInfo])
	if !ok {
		return nil, fmt.Errorf("could not extract info of thread %d", threadKey.EntityId)
	}
	return &threadInfo, nil
}

// GetEventThreadInfo get the information of the thread emitting the current event
func (ptds *ProcessTreeDS) GetEventThreadInfo(eventObj *trace.Event) (
	*datasource.TimeRelevantInfo[datasource.ThreadInfo], error,
) {
	queryKey := datasource.ThreadKey{
		EntityId: eventObj.ThreadEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
	}
	return ptds.GetThreadInfo(queryKey)
}

// GetProcessInfo query the datasource for the information of a specific process.
func (ptds *ProcessTreeDS) GetProcessInfo(processKey datasource.ProcKey) (
	*datasource.TimeRelevantInfo[datasource.ProcessInfo], error,
) {
	// Pick the process info from the data source
	procQueryAnswer, err := ptds.ds.Get(processKey)
	if err != nil {
		return nil, fmt.Errorf("could not find process for process %d", processKey.EntityId)
	}
	procInfo, ok := procQueryAnswer["process_info"].(datasource.TimeRelevantInfo[datasource.ProcessInfo])
	if !ok {
		return nil, fmt.Errorf("could not extract info of process %d", processKey.EntityId)
	}
	return &procInfo, nil
}

// GetEventProcessInfo get the information of the process emitting the current event
func (ptds *ProcessTreeDS) GetEventProcessInfo(eventObj *trace.Event) (
	*datasource.TimeRelevantInfo[datasource.ProcessInfo], error,
) {
	queryKey := datasource.ProcKey{
		EntityId: eventObj.ProcessEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
	}
	return ptds.GetProcessInfo(queryKey)
}

// GetProcessLineage query the datasource for the information of the process lineage of a
// specific process.
func (ptds *ProcessTreeDS) GetProcessLineage(lineageKey datasource.LineageKey) (
	*datasource.ProcessLineage, error,
) {
	// Pick the lineage info from the data source.
	lineageQueryAnswer, err := ptds.ds.Get(lineageKey)
	if err != nil {
		return nil, fmt.Errorf("could not find thread of process %d", lineageKey.EntityId)
	}
	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
	if !ok {
		return nil, fmt.Errorf("could not extract info of process %d", lineageKey.EntityId)
	}
	return &lineageInfo, nil
}

// GetEventProcessLineage get the process lineage information of the process emitting the
// current event.
func (ptds *ProcessTreeDS) GetEventProcessLineage(
	eventObj *trace.Event,
	maxDepth int,
) (*datasource.ProcessLineage, error) {
	queryKey := datasource.LineageKey{
		EntityId: eventObj.ProcessEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
		MaxDepth: maxDepth,
	}
	return ptds.GetProcessLineage(queryKey)
}
