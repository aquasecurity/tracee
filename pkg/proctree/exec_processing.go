package proctree

import (
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessExecEvent fills process information as any other general event,
// but add execution information.
func (tree *ProcessTree) ProcessExecEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	execInfo, err := parseExecArguments(event)
	if err != nil {
		return err
	}
	process.mutex.Lock()
	process.setExecInfo(time.Unix(0, int64(event.Timestamp)), execInfo)
	tnode, _ := process.getThread(event.HostThreadID)
	process.mutex.Unlock()
	tnode.mutex.Lock()
	tnode.setName(time.Unix(0, int64(event.Timestamp)), event.ProcessName)
	tnode.mutex.Unlock()

	return nil
}

// parseExecArguments get from the exec event all relevant information for the process tree - the
// binary information of the executed binary and the argv of the execution.
func parseExecArguments(event *trace.Event) (procExecInfo, error) {
	var execInfo procExecInfo
	cmd, err := helpers.GetTraceeSliceStringArgumentByName(*event, "argv")
	if err != nil {
		return execInfo, err
	}
	path, err := helpers.GetTraceeStringArgumentByName(*event, "pathname")
	if err != nil {
		return execInfo, err
	}
	ctime, err := helpers.GetTraceeUIntArgumentByName(*event, "ctime")
	if err != nil {
		return execInfo, err
	}
	inode, err := helpers.GetTraceeUIntArgumentByName(*event, "inode")
	if err != nil {
		return execInfo, err
	}
	dev, err := helpers.GetTraceeUIntArgumentByName(*event, "dev")
	if err != nil {
		return execInfo, err
	}

	hash, _ := helpers.GetTraceeStringArgumentByName(*event, "sha256")

	limitStringList(cmd)
	execInfo = procExecInfo{
		ExecutionBinary: fileInfo{
			path:   path,
			hash:   hash,
			ctime:  time.Unix(0, int64(ctime)),
			inode:  inode,
			device: dev,
		},
		Cmd: cmd,
	}
	return execInfo, nil
}

var maxStringLen = 40

// limitStringList shorten any string with length over maxStringLen to maxStringLen in given list.
// The last character will be set to '*' if the string was shortened.
func limitStringList(list []string) {
	for i, str := range list {
		if len(str) > maxStringLen {
			list[i] = str[:maxStringLen] + "*"
		}
	}
}
