package grpc

import (
	"context"
	"fmt"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/version"
	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
)

type TraceeService struct {
	pb.UnimplementedTraceeServiceServer
	tracee *tracee.Tracee
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
