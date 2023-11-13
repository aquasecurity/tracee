package printer

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

/*
ParquetEvent is used to define a schema for the parquet format.
We need to use a different structure than trace.Event because not all member types are supported by Parquet:
  - unit is not supported and must be converted to an int.
  - Value interface{} inside Argument is also not supported, it has no definite type

Event Conversion to ParquetEvent is required
*/
type ParquetEvent struct {
	Timestamp           int                 `parquet:"name=timestamp, type=INT64, logicaltype=TIMESTAMP, logicaltype.isadjustedtoutc=false, logicaltype.unit=NANOS"`
	ThreadStartTime     int                 `parquet:"name=threadStartTime, type=INT64"`
	ProcessorID         int                 `parquet:"name=processorId, type=INT64"`
	ProcessID           int                 `parquet:"name=processId, type=INT64"`
	CgroupID            int                 `parquet:"name=cgroupId, type=INT64, convertedtype=UINT_64"`
	ThreadID            int                 `parquet:"name=threadId, type=INT64"`
	ParentProcessID     int                 `parquet:"name=parentProcessId, type=INT64"`
	HostProcessID       int                 `parquet:"name=hostProcessId, type=INT64"`
	HostThreadID        int                 `parquet:"name=hostThreadId, type=INT64"`
	HostParentProcessID int                 `parquet:"name=hostParentProcessId, type=INT64"`
	UserID              int                 `parquet:"name=UserID, type=INT64"`
	MountNS             int                 `parquet:"name=mountNamespace, type=INT64"`
	PIDNS               int                 `parquet:"name=pidNamespace, type=INT64"`
	ProcessName         string              `parquet:"name=processName, type=BYTE_ARRAY"`
	Executable          ParquetFile         `parquet:"name=executable"`
	HostName            string              `parquet:"name=hostName, type=BYTE_ARRAY, convertedtype=UTF8"`
	ContainerID         string              `parquet:"name=containerId, type=BYTE_ARRAY, convertedtype=UTF8"`
	Container           ParquetContainer    `parquet:"name=container"`
	Kubernetes          ParquetKubernetes   `parquet:"name=kubernetes"`
	EventID             int                 `parquet:"name=eventId, type=INT64"`
	EventName           string              `parquet:"name=eventName, type=BYTE_ARRAY, convertedtype=UTF8"`
	MatchedPolicies     []string            `parquet:"name=matchedPolicies, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	ArgsNum             int                 `parquet:"name=argsNum, type=INT64"`
	ReturnValue         int                 `parquet:"name=returnValue, type=INT64"`
	Syscall             string              `parquet:"name=syscall, type=BYTE_ARRAY, convertedtype=UTF8"`
	StackAddresses      []int64             `parquet:"name=stackAddresses, type=MAP, convertedtype=LIST, valuetype=INT64, valueconvertedtype=UNIT_64"`
	ContextFlags        ParquetContextFlags `parquet:"name=contextFlags"`
	ThreadEntityId      int32               `parquet:"name=threadEntityId, type=INT32, convertedtype=UINT_32"`
	ProcessEntityId     int32               `parquet:"name=processEntityId, type=INT32, convertedtype=UINT_32"`
	ParentEntityId      int32               `parquet:"name=parentEntityId, type=INT32, convertedtype=UINT_32"`
	Args                string              `parquet:"name=args, type=BYTE_ARRAY, convertedtype=JSON"`
}

/*
The following structs are not necessary: ParquetContainer, ParquetKubernetes, ParquetContextFlags, ParquetFile.

The original structs in trace.go can be changed so they will have both json and parquet tag.
For example:

	type File struct {
		Path string `json:"path" parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
	}

	type Container struct {
		ID          string `json:"id,omitempty" parquet:"name=id, type=BYTE_ARRAY, convertedtype=UTF8"`
		Name        string `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
		ImageName   string `json:"image,omitempty" parquet:"name=image, type=BYTE_ARRAY, convertedtype=UTF8"`
		ImageDigest string `json:"imageDigest,omitempty" parquet:"name=imageDigest, type=BYTE_ARRAY, convertedtype=UTF8"`
	}
*/
type ParquetFile struct {
	Path string `parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
}

func toParquetFile(file trace.File) ParquetFile {
	return ParquetFile{
		Path: file.Path,
	}
}

type ParquetContainer struct {
	ID          string `parquet:"name=id, type=BYTE_ARRAY, convertedtype=UTF8"`
	Name        string `parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ImageName   string `parquet:"name=image, type=BYTE_ARRAY, convertedtype=UTF8"`
	ImageDigest string `parquet:"name=imageDigest, type=BYTE_ARRAY, convertedtype=UTF8"`
}

func toParquetContainer(container trace.Container) ParquetContainer {
	return ParquetContainer{
		ID:          container.ID,
		Name:        container.Name,
		ImageName:   container.ImageName,
		ImageDigest: container.ImageDigest,
	}
}

type ParquetKubernetes struct {
	PodName      string `parquet:"name=podName, type=BYTE_ARRAY, convertedtype=UTF8"`
	PodNamespace string `parquet:"name=podNamespace, type=BYTE_ARRAY, convertedtype=UTF8"`
	PodUID       string `parquet:"name=podUID, type=BYTE_ARRAY, convertedtype=UTF8"`
	PodSandbox   bool   `parquet:"name=podSandbox, type=BOOLEAN"`
}

func toParquetKubernetes(kubernetes trace.Kubernetes) ParquetKubernetes {
	return ParquetKubernetes{
		PodName:      kubernetes.PodName,
		PodNamespace: kubernetes.PodNamespace,
		PodUID:       kubernetes.PodUID,
		PodSandbox:   kubernetes.PodSandbox,
	}
}

type ParquetContextFlags struct {
	ContainerStarted bool `parquet:"name=containerStarted, type=BOOLEAN"`
	IsCompat         bool `parquet:"name=isCompat, type=BOOLEAN"`
}

func toParquetContextFlags(ctxFlags trace.ContextFlags) ParquetContextFlags {
	return ParquetContextFlags{
		ContainerStarted: ctxFlags.ContainerStarted,
		IsCompat:         ctxFlags.IsCompat,
	}
}

func toInt64Slice(uint64Slice []uint64) []int64 {
	int64Slice := make([]int64, len(uint64Slice))
	for i, val := range uint64Slice {
		int64Slice[i] = int64(val)
	}
	return int64Slice
}

func toJsonStr(toJson interface{}) string {

	argsJsonByte, err := json.Marshal(toJson)
	if err != nil {
		fmt.Println("Error marshaling to JSON:", err)
		return ""
	}
	return string(argsJsonByte)
}

func ToParquetEvent(event trace.Event) ParquetEvent {

	pqEvent := ParquetEvent{
		Timestamp:           event.Timestamp,
		ThreadStartTime:     event.ThreadStartTime,
		ProcessorID:         event.ProcessorID,
		ProcessID:           event.ProcessID,
		CgroupID:            int(event.CgroupID),
		ThreadID:            event.ThreadID,
		ParentProcessID:     event.ParentProcessID,
		HostProcessID:       event.HostProcessID,
		HostThreadID:        event.HostThreadID,
		HostParentProcessID: event.HostParentProcessID,
		UserID:              event.UserID,
		MountNS:             event.MountNS,
		PIDNS:               event.PIDNS,
		ProcessName:         event.ProcessName,
		Executable:          toParquetFile(event.Executable),
		HostName:            event.HostName,
		ContainerID:         event.ContainerID,
		Container:           toParquetContainer(event.Container),
		Kubernetes:          toParquetKubernetes(event.Kubernetes),
		EventID:             event.EventID,
		EventName:           event.EventName,
		MatchedPolicies:     event.MatchedPolicies,
		ArgsNum:             event.ArgsNum,
		ReturnValue:         event.ReturnValue,
		Syscall:             event.Syscall,
		StackAddresses:      toInt64Slice(event.StackAddresses),
		ContextFlags:        toParquetContextFlags(event.ContextFlags),
		ThreadEntityId:      int32(event.ThreadEntityId),
		ProcessEntityId:     int32(event.ProcessEntityId),
		ParentEntityId:      int32(event.ParentEntityId),
		Args:                toJsonStr(event.Args),
	}

	return pqEvent
}
