package apiutils

import (
	"fmt"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func ConvertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
	process := getProcess(e)
	container := getContainer(e)
	k8s := getK8s(e)

	var eventContext *pb.Context
	if process != nil || container != nil || k8s != nil {
		eventContext = &pb.Context{
			Process:   process,
			Container: container,
			K8S:       k8s,
		}
	}

	eventData, err := getEventData(e)
	if err != nil {
		return nil, err
	}

	var threat *pb.Threat
	if e.Metadata != nil {
		threat = GetThreat(e.Metadata.Description, e.Metadata.Properties)
	}

	event := &pb.Event{
		Id:   uint32(e.EventID),
		Name: e.EventName,
		Policies: &pb.Policies{
			Matched: e.MatchedPolicies,
		},
		Context: eventContext,
		Threat:  threat,

		Data: eventData,
	}

	if e.Timestamp != 0 {
		event.Timestamp = timestamppb.New(time.Unix(0, int64(e.Timestamp)))
	}

	return event, nil
}

func getProcess(e trace.Event) *pb.Process {
	var userStackTrace *pb.UserStackTrace

	if len(e.StackAddresses) > 0 {
		userStackTrace = &pb.UserStackTrace{
			Addresses: getStackAddress(e.StackAddresses),
		}
	}

	var threadStartTime *timestamp.Timestamp
	if e.ThreadStartTime != 0 {
		threadStartTime = timestamppb.New(time.Unix(0, int64(e.ThreadStartTime)))
	}

	var executable *pb.Executable
	if e.Executable.Path != "" {
		executable = &pb.Executable{Path: e.Executable.Path}
	}

	return &pb.Process{
		Executable:    executable,
		EntityId:      wrapperspb.UInt32(e.ProcessEntityId),
		Pid:           wrapperspb.UInt32(uint32(e.HostProcessID)),
		NamespacedPid: wrapperspb.UInt32(uint32(e.ProcessID)),
		RealUser: &pb.User{
			Id: wrapperspb.UInt32(uint32(e.UserID)),
		},
		Thread: &pb.Thread{
			Start:          threadStartTime,
			Name:           e.ProcessName,
			EntityId:       wrapperspb.UInt32(e.ThreadEntityId),
			Tid:            wrapperspb.UInt32(uint32(e.HostThreadID)),
			NamespacedTid:  wrapperspb.UInt32(uint32(e.ThreadID)),
			Syscall:        e.Syscall,
			Compat:         e.ContextFlags.ContainerStarted,
			UserStackTrace: userStackTrace,
		},
		Parent: &pb.Process{
			EntityId:      wrapperspb.UInt32(e.ParentEntityId),
			Pid:           wrapperspb.UInt32(uint32(e.HostParentProcessID)),
			NamespacedPid: wrapperspb.UInt32(uint32(e.ParentProcessID)),
		},
	}
}

func getContainer(e trace.Event) *pb.Container {
	if e.Container.ID == "" && e.Container.Name == "" {
		return nil
	}

	container := &pb.Container{
		Id:   e.Container.ID,
		Name: e.Container.Name,
	}

	if e.Container.ImageName != "" {
		var repoDigest []string
		if e.Container.ImageDigest != "" {
			repoDigest = []string{e.Container.ImageDigest}
		}

		container.Image = &pb.ContainerImage{
			Name:        e.Container.ImageName,
			RepoDigests: repoDigest,
		}
	}

	return container
}

func getK8s(e trace.Event) *pb.K8S {
	if e.Kubernetes.PodName == "" &&
		e.Kubernetes.PodUID == "" &&
		e.Kubernetes.PodNamespace == "" {
		return nil
	}

	return &pb.K8S{
		Namespace: &pb.K8SNamespace{
			Name: e.Kubernetes.PodNamespace,
		},
		Pod: &pb.Pod{
			Name: e.Kubernetes.PodName,
			Uid:  e.Kubernetes.PodUID,
		},
	}
}

func GetThreat(description string, metadata map[string]interface{}) *pb.Threat {
	if metadata == nil {
		return nil
	}
	// if metadata doesn't contain severity, it's not a threat,
	// severity is set when we have an event created from a signature
	// pkg/ebpf/fiding.go
	// pkg/cmd/initialize/sigs.go
	_, ok := metadata["Severity"]
	if !ok {
		return nil
	}

	var (
		mitreTactic        string
		mitreTechniqueId   string
		mitreTechniqueName string
		name               string
	)

	if _, ok := metadata["Category"]; ok {
		if val, ok := metadata["Category"].(string); ok {
			mitreTactic = val
		}
	}

	if _, ok := metadata["external_id"]; ok {
		if val, ok := metadata["external_id"].(string); ok {
			mitreTechniqueId = val
		}
	}

	if _, ok := metadata["Technique"]; ok {
		if val, ok := metadata["Technique"].(string); ok {
			mitreTechniqueName = val
		}
	}

	if _, ok := metadata["signatureName"]; ok {
		if val, ok := metadata["signatureName"].(string); ok {
			name = val
		}
	}

	properties := make(map[string]string)

	for k, v := range metadata {
		if k == "Category" ||
			k == "external_id" ||
			k == "Technique" ||
			k == "Severity" ||
			k == "signatureName" {
			continue
		}

		properties[k] = fmt.Sprint(v)
	}

	return &pb.Threat{
		Description: description,
		Mitre: &pb.Mitre{
			Tactic: &pb.MitreTactic{
				Name: mitreTactic,
			},
			Technique: &pb.MitreTechnique{
				Id:   mitreTechniqueId,
				Name: mitreTechniqueName,
			},
		},
		Severity:   getSeverity(metadata),
		Name:       name,
		Properties: properties,
	}
}

func getSeverity(metadata map[string]interface{}) pb.Severity {
	switch metadata["Severity"].(int) {
	case 0:
		return pb.Severity_INFO
	case 1:
		return pb.Severity_LOW
	case 2:
		return pb.Severity_MEDIUM
	case 3:
		return pb.Severity_HIGH
	case 4:
		return pb.Severity_CRITICAL
	}

	return -1
}

func getStackAddress(stackAddresses []uint64) []*pb.StackAddress {
	var out []*pb.StackAddress
	for _, addr := range stackAddresses {
		out = append(out, &pb.StackAddress{Address: addr})
	}

	return out
}
