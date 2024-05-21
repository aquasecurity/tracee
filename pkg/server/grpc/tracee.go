package grpc

import (
	"context"
	"fmt"

	"github.com/mennanov/fmutils"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/apiutils"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/streams"
	"github.com/aquasecurity/tracee/pkg/version"
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
		mask.Filter(e)

		err = grpcStream.Send(&pb.StreamEventsResponse{Event: e.Proto()})
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

func (s *TraceeService) GetEventDefinitions(ctx context.Context, in *pb.GetEventDefinitionsRequest) (*pb.GetEventDefinitionsResponse, error) {
	definitions, err := getDefinitions(in)
	if err != nil {
		return nil, err
	}

	out := make([]*pb.EventDefinition, 0, len(definitions))

	for _, d := range definitions {
		ed := convertDefinitionToProto(d)
		out = append(out, ed)
	}

	return &pb.GetEventDefinitionsResponse{
		Definitions: out,
	}, nil
}

func (s *TraceeService) GetVersion(ctx context.Context, in *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{Version: version.GetVersion()}, nil
}

func getDefinitions(in *pb.GetEventDefinitionsRequest) ([]events.Definition, error) {
	if len(in.EventNames) == 0 {
		return events.Core.GetDefinitions(), nil
	}

	definitions := make([]events.Definition, 0, len(in.EventNames))

	for _, name := range in.EventNames {
		id, ok := events.Core.GetDefinitionIDByName(name)
		if !ok {
			return nil, fmt.Errorf("event %s not found", name)
		}

		definition := events.Core.GetDefinitionByID(id)
		definitions = append(definitions, definition)
	}

	return definitions, nil
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
		// threat description is empty because it is the same as the event definition description
		Threat: apiutils.GetThreat("", d.GetProperties()),
	}
}
