package pcaps

import (
	"encoding/json"
	"math"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/types/trace"
)

var packetContextVersion = "1.0"

// This struct represents the context of a packet capture.
// Packet captures can be per process, command, container or a single capture,
// which affects the context info relevant to it.
// The context contains information that is supposed to be constant for the
// entire capture, although this may not always be the case.
// For example, if a process changes its name, this won't be reflected in the
// capture's context information.
type PacketContext struct {
	Version string `json:"version"`

	// Present for container, command and process captures
	Container  *ContainerContext  `json:"container,omitempty"`
	Kubernetes *KubernetesContext `json:"kubernetes,omitempty"`
	HostName   string             `json:"hostName,omitempty"`

	// Present for command and process captures
	ProcessName string `json:"processName,omitempty"`

	// Present for process captures
	Process *ProcessContext `json:"process,omitempty"`
}

type ProcessContext struct {
	ThreadStartTime     int    `json:"threadStartTime"`
	ProcessID           int    `json:"processId"`
	CgroupID            uint   `json:"cgroupId"`
	ThreadID            int    `json:"threadId"`
	ParentProcessID     int    `json:"parentProcessId"`
	HostProcessID       int    `json:"hostProcessId"`
	HostThreadID        int    `json:"hostThreadId"`
	HostParentProcessID int    `json:"hostParentProcessId"`
	UserID              int    `json:"userId"`
	MountNS             int    `json:"mountNamespace"`
	PIDNS               int    `json:"pidNamespace"`
	Executable          string `json:"executable"`
}

type ContainerContext struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	ImageName   string `json:"image,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
}

type KubernetesContext struct {
	PodName      string `json:"podName,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
	PodUID       string `json:"podUID,omitempty"`
	PodSandbox   bool   `json:"podSandbox,omitempty"`
}

func initPacketContext(event *trace.Event, t PcapType) PacketContext {
	ctx := PacketContext{Version: packetContextVersion}

	if t == Container || t == Command || t == Process {
		ctx.Container = &ContainerContext{
			ID:          event.Container.ID,
			Name:        event.Container.Name,
			ImageName:   event.Container.ImageName,
			ImageDigest: event.Container.ImageDigest,
		}
		ctx.Kubernetes = &KubernetesContext{
			PodName:      event.Kubernetes.PodName,
			PodNamespace: event.Kubernetes.PodNamespace,
			PodUID:       event.Kubernetes.PodUID,
			PodSandbox:   event.Kubernetes.PodSandbox,
		}
		ctx.HostName = event.HostName
	}

	if t == Command || t == Process {
		ctx.ProcessName = event.ProcessName
	}

	if t == Process {
		ctx.Process = &ProcessContext{
			ThreadStartTime:     event.ThreadStartTime,
			ProcessID:           event.ProcessID,
			CgroupID:            event.CgroupID,
			ThreadID:            event.ThreadID,
			ParentProcessID:     event.ParentProcessID,
			HostProcessID:       event.HostProcessID,
			HostThreadID:        event.HostThreadID,
			HostParentProcessID: event.HostParentProcessID,
			UserID:              event.UserID,
			MountNS:             event.MountNS,
			PIDNS:               event.PIDNS,
			Executable:          event.Executable.Path,
		}
	}

	return ctx
}

func GenerateInterface(event *trace.Event, t PcapType) (pcapgo.NgInterface, error) {
	packetContext := initPacketContext(event, t)

	descBytes, err := json.Marshal(packetContext)
	if err != nil {
		return pcapgo.NgInterface{}, errfmt.WrapError(err)
	}
	desc := string(descBytes)

	return pcapgo.NgInterface{ // https://www.tcpdump.org/linktypes.html
		Name:        "tracee",
		Comment:     "tracee packet capture",
		Description: desc,
		LinkType:    layers.LinkTypeNull, // layer2 is 4 bytes (or 32bit)
		SnapLength:  uint32(math.MaxUint32),
	}, nil
}
