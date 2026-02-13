package stress

import (
	"strings"
	"testing"
)

func TestEventSpecsFromFilesAndCLI_FileOnly_SingleScenarioImplicit(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid_single_scenario.yaml"},
		nil, false, nil,
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	if len(specs) != 1 || specs[0] != "security_file_open" {
		t.Errorf("expected [security_file_open], got %v", specs)
	}
}

func TestEventSpecsFromFilesAndCLI_FileWithScenario(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid.yaml"},
		[]string{"smoke"}, false, nil,
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	want := []string{"security_file_open", "ptrace"}
	if len(specs) != len(want) || specs[0] != want[0] || specs[1] != want[1] {
		t.Errorf("expected %v, got %v", want, specs)
	}
}

func TestEventSpecsFromFilesAndCLI_FileWithMultipleScenarios(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid.yaml"},
		[]string{"filesystem", "smoke"}, false, nil,
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	// filesystem has one group with magic_write:instances=2; smoke has security_file_open, ptrace
	if len(specs) != 3 {
		t.Errorf("expected 3 specs (filesystem + smoke), got %d: %v", len(specs), specs)
	}
	if !strings.Contains(specs[0], "magic_write") {
		t.Errorf("first spec should be from filesystem: %q", specs[0])
	}
}

func TestEventSpecsFromFilesAndCLI_FileWithAllScenarios(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid.yaml"},
		nil, true, nil,
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	// smoke (2) + filesystem (1 from group) = 3
	if len(specs) != 3 {
		t.Errorf("expected 3 specs (all scenarios), got %d: %v", len(specs), specs)
	}
}

func TestEventSpecsFromFilesAndCLI_FileAndCLI_MergeOrder(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid_single_scenario.yaml"},
		nil, false, []string{"ptrace"},
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	want := []string{"security_file_open", "ptrace"}
	if len(specs) != 2 || specs[0] != want[0] || specs[1] != want[1] {
		t.Errorf("expected scenario then CLI order %v, got %v", want, specs)
	}
}

func TestEventSpecsFromFilesAndCLI_CLIOnly(t *testing.T) {
	specs, err := eventSpecsFromFilesAndCLI(
		nil, nil, false, []string{"security_file_open", "ptrace"},
	)
	if err != nil {
		t.Fatalf("eventSpecsFromFilesAndCLI: %v", err)
	}
	want := []string{"security_file_open", "ptrace"}
	if len(specs) != 2 || specs[0] != want[0] || specs[1] != want[1] {
		t.Errorf("expected %v, got %v", want, specs)
	}
}

func TestEventSpecsFromFilesAndCLI_Empty_Error(t *testing.T) {
	_, err := eventSpecsFromFilesAndCLI(nil, nil, false, nil)
	if err == nil {
		t.Fatal("expected error when no events from any source")
	}
	if !strings.Contains(err.Error(), "at least one event") {
		t.Errorf("error should mention at least one event: %v", err)
	}
}

func TestEventSpecsFromFilesAndCLI_AllScenariosAndNames_Error(t *testing.T) {
	_, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/suite_valid.yaml"},
		[]string{"smoke"}, true, nil,
	)
	if err == nil {
		t.Fatal("expected error when both --scenario and --all-scenarios")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutually exclusive: %v", err)
	}
}

func TestEventSpecsFromFilesAndCLI_FileNotFound_Error(t *testing.T) {
	_, err := eventSpecsFromFilesAndCLI(
		[]string{"testdata/nonexistent.yaml"},
		[]string{"smoke"}, false, nil,
	)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestUniqueEventNames(t *testing.T) {
	triggers := []triggerConfig{
		{event: "a", instances: 1, ops: 100, sleep: "10ns"},
		{event: "b", instances: 1, ops: 100, sleep: "10ns"},
		{event: "a", instances: 2, ops: 200, sleep: "1ms"},
	}
	got := uniqueEventNames(triggers)
	want := []string{"a", "b"}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("uniqueEventNames: got %v, want %v", got, want)
	}
}
