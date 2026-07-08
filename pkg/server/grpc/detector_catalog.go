package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
)

const (
	signaturesTag = "signatures"
	detectorsTag  = "detectors"
)

func (s *TraceeService) GetDetectorsCatalog(ctx context.Context, in *pb.GetDetectorsCatalogRequest) (*pb.GetDetectorsCatalogResponse, error) {
	entries, err := buildDetectorsCatalog(in)
	if err != nil {
		return nil, err
	}

	return &pb.GetDetectorsCatalogResponse{Entries: entries}, nil
}

func buildDetectorsCatalog(in *pb.GetDetectorsCatalogRequest) ([]*pb.DetectorCatalogEntry, error) {
	if in == nil {
		in = &pb.GetDetectorsCatalogRequest{}
	}

	if err := validateDetectorCatalogFilters(in); err != nil {
		return nil, err
	}

	entries := make([]*pb.DetectorCatalogEntry, 0)

	for _, d := range events.Core.GetDefinitions() {
		if !isCatalogDefinition(d) {
			continue
		}

		detectorID, detectorName, ok := extractCatalogIdentity(d)
		if !ok {
			logger.Warnw("Skipping catalog definition without identity", "event", d.GetName())
			continue
		}

		if !matchesDetectorCatalogFilters(in, detectorID, d.GetName()) {
			continue
		}

		entries = append(entries, convertDefinitionToCatalogEntry(d, detectorID, detectorName, d.GetProperties()))
	}

	return entries, nil
}

func validateDetectorCatalogFilters(in *pb.GetDetectorsCatalogRequest) error {
	for _, detectorID := range in.GetDetectorIds() {
		if !detectorCatalogContainsID(detectorID) {
			return status.Errorf(codes.InvalidArgument, "detector_id %s not found", detectorID)
		}
	}

	for _, eventName := range in.GetEventNames() {
		definition := events.Core.GetDefinitionByName(eventName)
		if definition.NotValid() || !isCatalogDefinition(definition) {
			return status.Errorf(codes.InvalidArgument, "event %s not found", eventName)
		}
	}

	return nil
}

func detectorCatalogContainsID(detectorID string) bool {
	for _, d := range events.Core.GetDefinitions() {
		if !isCatalogDefinition(d) {
			continue
		}
		id, _, ok := extractCatalogIdentity(d)
		if ok && id == detectorID {
			return true
		}
	}
	return false
}

func matchesDetectorCatalogFilters(in *pb.GetDetectorsCatalogRequest, detectorID, eventName string) bool {
	if len(in.GetDetectorIds()) > 0 && !containsString(in.GetDetectorIds(), detectorID) {
		return false
	}
	if len(in.GetEventNames()) > 0 && !containsString(in.GetEventNames(), eventName) {
		return false
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func definitionHasTag(d events.Definition, tag string) bool {
	for _, t := range d.GetSets() {
		if t == tag {
			return true
		}
	}
	return false
}

func isCatalogDefinition(d events.Definition) bool {
	return definitionHasTag(d, signaturesTag) || definitionHasTag(d, detectorsTag)
}

func extractCatalogIdentity(d events.Definition) (detectorID, detectorName string, ok bool) {
	props := d.GetProperties()

	if sigID, ok := props["signatureID"].(string); ok && sigID != "" {
		var sigName string
		if name, nameOK := props["signatureName"].(string); nameOK {
			sigName = name
		}
		return sigID, sigName, true
	}

	if id, ok := props["detectorID"].(string); ok && id != "" {
		return id, d.GetName(), true
	}

	return "", "", false
}

func convertDefinitionToCatalogEntry(d events.Definition, detectorID, detectorName string, props map[string]interface{}) *pb.DetectorCatalogEntry {
	v := d.GetVersion()

	return &pb.DetectorCatalogEntry{
		DetectorId:   sanitizeStringForProtobuf(detectorID),
		DetectorName: sanitizeStringForProtobuf(detectorName),
		EventName:    sanitizeStringForProtobuf(d.GetName()),
		Version: &pb.Version{
			Major: v.Major(),
			Minor: v.Minor(),
			Patch: v.Patch(),
		},
		Description: sanitizeStringForProtobuf(d.GetDescription()),
		Tags:        sanitizeStringSliceForProtobuf(d.GetSets()),
		Properties:  propertiesToProtoMap(props),
	}
}

func propertiesToProtoMap(props map[string]interface{}) map[string]string {
	if len(props) == 0 {
		return nil
	}

	sanitized := sanitizeMapForProtobuf(props)
	out := make(map[string]string, len(sanitized))
	for k, v := range sanitized {
		out[sanitizeStringForProtobuf(k)] = sanitizeStringForProtobuf(fmt.Sprint(v))
	}

	return out
}

func sanitizeStringSliceForProtobuf(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, len(values))
	for i, v := range values {
		out[i] = sanitizeStringForProtobuf(v)
	}
	return out
}
