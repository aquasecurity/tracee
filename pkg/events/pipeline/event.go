package pipeline

import (
	"github.com/aquasecurity/tracee/types/trace"
)

type Event struct {
	// 8-byte aligned fields (int, uint, uint64)
	Timestamp             int    `json:"timestamp"`
	ThreadStartTime       int    `json:"threadStartTime"`
	ProcessorID           int    `json:"processorId"`
	ProcessID             int    `json:"processId"`
	ThreadID              int    `json:"threadId"`
	ParentProcessID       int    `json:"parentProcessId"`
	HostProcessID         int    `json:"hostProcessId"`
	HostThreadID          int    `json:"hostThreadId"`
	HostParentProcessID   int    `json:"hostParentProcessId"`
	UserID                int    `json:"userId"`
	MountNS               int    `json:"mountNamespace"`
	PIDNS                 int    `json:"pidNamespace"`
	EventID               int    `json:"eventId,string"`
	ArgsNum               int    `json:"argsNum"`
	ReturnValue           int    `json:"returnValue"`
	CgroupID              uint   `json:"cgroupId"`
	MatchedPoliciesKernel uint64 `json:"-"`
	MatchedPoliciesUser   uint64 `json:"-"`

	// 24-byte slice headers
	StackAddresses  []uint64         `json:"stackAddresses"`
	MatchedPolicies []string         `json:"matchedPolicies,omitempty"`
	Args            []trace.Argument `json:"args"`

	// 8-byte pointers
	Metadata *trace.Metadata `json:"metadata,omitempty"`

	// 4-byte fields
	ThreadEntityId  uint32 `json:"threadEntityId"`
	ProcessEntityId uint32 `json:"processEntityId"`
	ParentEntityId  uint32 `json:"parentEntityId"`

	// 2-byte fields
	PoliciesVersion uint16 `json:"-"`

	// 8-byte strings (string headers are 8 bytes)
	ProcessName string `json:"processName"`
	HostName    string `json:"hostName"`
	ContainerID string `json:"containerId"`
	EventName   string `json:"eventName"`
	Syscall     string `json:"syscall"`

	// Custom types (structs or pointers)
	Executable   trace.File         `json:"executable"`
	Container    trace.Container    `json:"container,omitempty"`
	Kubernetes   trace.Kubernetes   `json:"kubernetes,omitempty"`
	ContextFlags trace.ContextFlags `json:"contextFlags"`
}

// Getter methods
func (e *Event) GetTimestamp() int {
	return e.Timestamp
}

func (e *Event) GetThreadStartTime() int {
	return e.ThreadStartTime
}

func (e *Event) GetProcessorID() int {
	return e.ProcessorID
}

func (e *Event) GetProcessID() int {
	return e.ProcessID
}

func (e *Event) GetCgroupID() uint {
	return e.CgroupID
}

func (e *Event) GetThreadID() int {
	return e.ThreadID
}

func (e *Event) GetParentProcessID() int {
	return e.ParentProcessID
}

func (e *Event) GetHostProcessID() int {
	return e.HostProcessID
}

func (e *Event) GetHostThreadID() int {
	return e.HostThreadID
}

func (e *Event) GetHostParentProcessID() int {
	return e.HostParentProcessID
}

func (e *Event) GetUserID() int {
	return e.UserID
}

func (e *Event) GetMountNS() int {
	return e.MountNS
}

func (e *Event) GetPIDNS() int {
	return e.PIDNS
}

func (e *Event) GetProcessName() string {
	return e.ProcessName
}

func (e *Event) GetExecutable() trace.File {
	return e.Executable
}

func (e *Event) GetHostName() string {
	return e.HostName
}

func (e *Event) GetContainerID() string {
	return e.ContainerID
}

func (e *Event) GetContainer() trace.Container {
	return e.Container
}

func (e *Event) GetKubernetes() trace.Kubernetes {
	return e.Kubernetes
}

func (e *Event) GetEventID() int {
	return e.EventID
}

func (e *Event) GetEventName() string {
	return e.EventName
}

func (e *Event) GetMatchedPolicies() []string {
	return e.MatchedPolicies
}

func (e *Event) GetArgsNum() int {
	return e.ArgsNum
}

func (e *Event) GetReturnValue() int {
	return e.ReturnValue
}

func (e *Event) GetSyscall() string {
	return e.Syscall
}

func (e *Event) GetStackAddresses() []uint64 {
	return e.StackAddresses
}

func (e *Event) GetContextFlags() trace.ContextFlags {
	return e.ContextFlags
}

func (e *Event) GetThreadEntityId() uint32 {
	return e.ThreadEntityId
}

func (e *Event) GetProcessEntityId() uint32 {
	return e.ProcessEntityId
}

func (e *Event) GetParentEntityId() uint32 {
	return e.ParentEntityId
}

func (e *Event) GetArgs() []trace.Argument {
	return e.Args
}

func (e *Event) GetMetadata() *trace.Metadata {
	return e.Metadata
}
