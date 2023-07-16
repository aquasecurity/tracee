package proctree

import (
	"encoding/json"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
)

// DataSource is an implementation to detect.Datasource interface, enveloping the ProcessTree type.
// It exposes all the exported querying functions of the tree using the interface methods.
type DataSource struct {
	procTree *ProcessTree
}

func NewDataSource(processTree *ProcessTree) *DataSource {
	return &DataSource{procTree: processTree}
}

func (ptds *DataSource) Get(key interface{}) (map[string]interface{}, error) {
	switch typedKey := key.(type) {
	case datasource.ProcKey:
		procInfo, err := ptds.procTree.GetProcessInfo(typedKey.Pid, typedKey.Time)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_info": procInfo,
		}, nil
	case datasource.ThreadKey:
		threadInfo, err := ptds.procTree.GetThreadInfo(typedKey.Tid, typedKey.Time)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"thread_info": threadInfo,
		}, nil
	case datasource.LineageKey:
		procLineage, err := ptds.procTree.GetProcessLineage(typedKey.Pid, typedKey.Time, typedKey.MaxDepth)
		if err != nil {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_lineage": procLineage,
		}, nil
	default:
		return nil, detect.ErrKeyNotSupported
	}
}

func (ptds *DataSource) Keys() []string {
	return []string{"datasource.ProcKey", "datasource.ThreadKey", "datasource.LineageKey"}
}

func (ptds *DataSource) Schema() string {
	schemaMap := map[string]string{
		"process_info":    "datasource.ProcessInfo",
		"thread_info":     "datasource.ThreadInfo",
		"process_lineage": "datasource.ProcessLineage",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ptds *DataSource) Version() uint {
	return 1
}

func (ptds *DataSource) Namespace() string {
	return "tracee"
}

func (ptds *DataSource) ID() string {
	return "process_tree"
}
