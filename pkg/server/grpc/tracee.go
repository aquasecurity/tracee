package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/mennanov/fmutils"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
)

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
	tracee *tracee.Tracee
}

func (s *TraceeService) StreamEvents(in *pb.StreamEventsRequest, grpcStream pb.TraceeService_StreamEventsServer) error {
	var stream *streams.Stream
	var err error

	if len(in.Policies) == 0 {
		stream = s.tracee.SubscribeAll()
	} else {
		stream, err = s.tracee.Subscribe(in.Policies)
		if err != nil {
			return err
		}
	}
	defer s.tracee.Unsubscribe(stream)

	mask := fmutils.NestedMaskFromPaths(in.GetMask().GetPaths())

	for e := range stream.ReceiveEvents() {
		// TODO: this conversion is temporary, we will use the new event structure
		// on tracee internals, so the event received by the stream will already be a proto
		eventProto, err := convertTraceeEventToProto(e)
		if err != nil {
			logger.Errorw("error can't create event proto: " + err.Error())
			continue
		}

		mask.Filter(eventProto)

		err = grpcStream.Send(&pb.StreamEventsResponse{Event: eventProto})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *TraceeService) EnableEvent(ctx context.Context, in *pb.EnableEventRequest) (*pb.EnableEventResponse, error) {
	err := s.tracee.EnableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.EnableEventResponse{}, nil
}

func (s *TraceeService) DisableEvent(ctx context.Context, in *pb.DisableEventRequest) (*pb.DisableEventResponse, error) {
	err := s.tracee.DisableEvent(in.Name)
	if err != nil {
		return nil, err
	}

	return &pb.DisableEventResponse{}, nil
}

func (s *TraceeService) GetEventDefinition(ctx context.Context, in *pb.GetEventDefinitionRequest) (*pb.GetEventDefinitionResponse, error) {
	definitions, err := getDefinitions(in)
	if err != nil {
		return nil, err
	}

	out := make([]*pb.EventDefinition, 0, len(definitions))

	for _, d := range definitions {
		ed := convertDefinitionToProto(d)
		out = append(out, ed)
	}

	return &pb.GetEventDefinitionResponse{
		Definitions: out,
	}, nil
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}

func getDefinitions(in *pb.GetEventDefinitionRequest) ([]events.Definition, error) {
	if in.Name == "" {
		return events.Core.GetDefinitions(), nil
	}

	id, ok := events.Core.GetDefinitionIDByName(in.Name)
	if !ok {
		return nil, fmt.Errorf("event %s not found", in.Name)
	}

	return []events.Definition{events.Core.GetDefinitionByID(id)}, nil
}

func convertDefinitionToProto(d events.Definition) *pb.EventDefinition {
	v := &pb.Version{
		Major: d.GetVersion().Major(),
		Minor: d.GetVersion().Minor(),
		Patch: d.GetVersion().Patch(),
	}

	return &pb.EventDefinition{
		Id:          int32(d.GetID()),
		Name:        d.GetName(),
		Version:     v,
		Description: d.GetDescription(),
		Tags:        d.GetSets(),
	}
}

func convertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
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

	event := &pb.Event{
		Id:   uint32(e.EventID),
		Name: e.EventName,
		Policies: &pb.Policies{
			Matched: e.MatchedPolicies,
		},
		Context:   eventContext,
		Threat:    getThreat(e),
		EventData: eventData,
	}

	if e.Timestamp != 0 {
		event.Timestamp = timestamppb.New(time.Unix(int64(e.Timestamp), 0))
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
		threadStartTime = timestamppb.New(time.Unix(int64(e.ThreadStartTime), 0))
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

func getThreat(e trace.Event) *pb.Threat {
	if e.Metadata == nil || e.Metadata.Properties == nil {
		return nil
	}
	// if metadata doesn't contain severity, it's not a threat,
	// severity is set when we have a finding from the signature engine
	// pkg/ebpf/fiding.go
	_, ok := e.Metadata.Properties["Severity"]
	if !ok {
		return nil
	}

	var (
		mitreTactic        string
		mitreTechniqueId   string
		mitreTechniqueName string
	)

	if _, ok := e.Metadata.Properties["Category"]; ok {
		if val, ok := e.Metadata.Properties["Category"].(string); ok {
			mitreTactic = val
		}
	}

	if _, ok := e.Metadata.Properties["external_id"]; ok {
		if val, ok := e.Metadata.Properties["external_id"].(string); ok {
			mitreTechniqueId = val
		}
	}

	if _, ok := e.Metadata.Properties["Technique"]; ok {
		if val, ok := e.Metadata.Properties["Technique"].(string); ok {
			mitreTechniqueName = val
		}
	}

	return &pb.Threat{
		Description: e.Metadata.Description,
		Mitre: &pb.Mitre{
			Tactic: &pb.MitreTactic{
				Name: mitreTactic,
			},
			Technique: &pb.MitreTechnique{
				Id:   mitreTechniqueId,
				Name: mitreTechniqueName,
			},
		},
		Severity: getSeverity(e),
	}
}

func getSeverity(e trace.Event) pb.Severity {
	switch e.Metadata.Properties["Severity"].(int) {
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
