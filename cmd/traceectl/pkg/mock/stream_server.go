package mock

import (
	"sort"
	"strings"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (s *MockServiceServer) StreamEvents(req *pb.StreamEventsRequest, stream pb.TraceeService_StreamEventsServer) error {
	mockEvents := CreateEventsFromPolicies(req.Policies)
	for _, event := range mockEvents {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}
func generateEvent(policy []string) *pb.Event {
	return &pb.Event{
		Policies: &pb.Policies{Matched: policy},
	}
}
func CreateEventsFromPolicies(policies []string) []*pb.StreamEventsResponse {
	if len(policies) == 0 {
		return []*pb.StreamEventsResponse{
			{Event: generateEvent([]string{""})},
		}
	}
	sort.Strings(policies)
	var results []*pb.StreamEventsResponse
	combinations := generateCombinations(policies)
	sort.SliceStable(combinations, func(i, j int) bool {
		if len(combinations[i]) != len(combinations[j]) {
			return len(combinations[i]) < len(combinations[j])
		}
		return strings.Join(combinations[i], ",") < strings.Join(combinations[j], ",")
	})
	for _, combo := range combinations {
		results = append(results, &pb.StreamEventsResponse{
			Event: generateEvent(combo),
		})
	}

	return results
}
func generateCombinations(policies []string) [][]string {
	var result [][]string
	n := len(policies)
	var helper func(start int, combo []string)
	helper = func(start int, combo []string) {
		if len(combo) > 0 {
			combinationCopy := append([]string{}, combo...)
			result = append(result, combinationCopy)
		}
		for i := start; i < n; i++ {
			helper(i+1, append(combo, policies[i]))
		}
	}
	helper(0, []string{})
	return result
}
