package mock

import (
	"sort"
	"strings"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

/*
\stream events
*/

// StreamEvents simulates the server-side streaming RPC
// and the server will return a stream of events based on the request
func (s *MockServiceServer) StreamEvents(req *pb.StreamEventsRequest, stream pb.TraceeService_StreamEventsServer) error {
	// Define mock events to send
	mockEvents := CreateEventsFromPolicies(req.Policies)

	// Simulate streaming of events with delays
	for _, event := range mockEvents {
		if err := stream.Send(event); err != nil {
			return err
		}

	}
	time.Sleep(100 * time.Millisecond) // Simulate delay between events
	return nil
}

// generateEvent creates a new event with the given policies.
func generateEvent(policy []string) *pb.Event {
	return &pb.Event{
		Policies: &pb.Policies{Matched: policy},
	}
}

// CreateEventsFromPolicies generates events based on the provided policies.
// It returns all unique combinations of the policies.
func CreateEventsFromPolicies(policies []string) []*pb.StreamEventsResponse {
	if len(policies) == 0 {
		// If no policies are provided, return an event with an empty policy.
		return []*pb.StreamEventsResponse{
			{Event: generateEvent([]string{""})},
		}
	}

	// Sort policies to ensure lexicographical order.
	// can make a comment if you want
	sort.Strings(policies)

	// Generate all unique combinations of the policies.
	var results []*pb.StreamEventsResponse
	combinations := generateCombinations(policies)

	// Sort combinations by length first, and then lexicographically.
	sort.SliceStable(combinations, func(i, j int) bool {
		// Sort by length of the combination first
		if len(combinations[i]) != len(combinations[j]) {
			return len(combinations[i]) < len(combinations[j])
		}
		// If lengths are the same, sort lexicographically
		return strings.Join(combinations[i], ",") < strings.Join(combinations[j], ",")
	})

	// For each combination, create a unique event.
	for _, combo := range combinations {
		results = append(results, &pb.StreamEventsResponse{
			Event: generateEvent(combo),
		})
	}

	return results
}

// generateCombinations returns all unique combinations of the input policies.
func generateCombinations(policies []string) [][]string {
	var result [][]string
	n := len(policies)

	// Use a recursive helper function to generate combinations.
	var helper func(start int, combo []string)
	helper = func(start int, combo []string) {
		// Add the current combination to the result.
		if len(combo) > 0 {
			// Make a copy of the combo to avoid mutations.
			combinationCopy := append([]string{}, combo...)
			result = append(result, combinationCopy)
		}

		// Iterate over the remaining elements to form combinations.
		for i := start; i < n; i++ {
			helper(i+1, append(combo, policies[i]))
		}
	}

	// Start with an empty combination.
	helper(0, []string{})

	return result
}
