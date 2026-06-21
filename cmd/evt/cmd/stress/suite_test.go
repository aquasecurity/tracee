package stress

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLoadSuitesFromFiles_Valid(t *testing.T) {
	suites, err := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	if err != nil {
		t.Fatalf("LoadSuitesFromFiles: %v", err)
	}
	if len(suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites))
	}
	s := suites[0]
	if s.Name != "test-suite" {
		t.Errorf("suite name: got %q", s.Name)
	}
	if len(s.Scenarios) != 2 {
		t.Fatalf("expected 2 scenarios, got %d", len(s.Scenarios))
	}
	if s.Scenarios[0].Name != "smoke" || len(s.Scenarios[0].Events) != 2 {
		t.Errorf("scenario smoke: got name %q, events %d", s.Scenarios[0].Name, len(s.Scenarios[0].Events))
	}
	if s.Scenarios[1].Name != "filesystem" || len(s.Scenarios[1].Groups) != 1 {
		t.Errorf("scenario filesystem: got name %q, groups %d", s.Scenarios[1].Name, len(s.Scenarios[1].Groups))
	}
}

func TestLoadSuitesFromFiles_InvalidNoScenarios(t *testing.T) {
	_, err := LoadSuitesFromFiles([]string{"testdata/suite_invalid_no_scenarios.yaml"})
	if err == nil {
		t.Fatal("expected error for missing scenarios")
	}
	if len(err.Error()) == 0 {
		t.Fatal("error message should not be empty")
	}
}

func TestLoadSuitesFromFiles_InvalidEmptyScenarios(t *testing.T) {
	_, err := LoadSuitesFromFiles([]string{"testdata/suite_invalid_empty_scenarios.yaml"})
	if err == nil {
		t.Fatal("expected error for empty scenarios")
	}
}

func TestLoadSuitesFromFiles_InvalidDuplicateScenarioName(t *testing.T) {
	_, err := LoadSuitesFromFiles([]string{"testdata/suite_invalid_duplicate_scenario_name.yaml"})
	if err == nil {
		t.Fatal("expected error for duplicate scenario name")
	}
	if len(err.Error()) == 0 {
		t.Fatal("error message should not be empty")
	}
}

func TestLoadSuitesFromFiles_InvalidScenarioNoEvents(t *testing.T) {
	_, err := LoadSuitesFromFiles([]string{"testdata/suite_invalid_scenario_no_events.yaml"})
	if err == nil {
		t.Fatal("expected error for scenario with no events or groups")
	}
}

func TestLoadSuitesFromFiles_FileNotFound(t *testing.T) {
	_, err := LoadSuitesFromFiles([]string{"testdata/nonexistent.yaml"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(errors.Unwrap(err)) {
		t.Errorf("expected wrapped ErrNotExist, got: %v", err)
	}
}

func TestLoadSuitesFromFiles_MultipleFiles(t *testing.T) {
	suites, err := LoadSuitesFromFiles([]string{
		"testdata/suite_valid.yaml",
		"testdata/suite_valid.yaml",
	})
	if err != nil {
		t.Fatalf("LoadSuitesFromFiles: %v", err)
	}
	if len(suites) != 2 {
		t.Fatalf("expected 2 suites, got %d", len(suites))
	}
}

func TestFlattenScenario_EventsOnly(t *testing.T) {
	sc := &Scenario{
		Name:   "x",
		Events: []string{"e1", "e2"},
	}
	got := FlattenScenario(sc)
	want := []string{"e1", "e2"}
	if len(got) != len(want) || (len(got) > 0 && (got[0] != want[0] || got[1] != want[1])) {
		t.Errorf("FlattenScenario(events only): got %v, want %v", got, want)
	}
}

func TestFlattenScenario_GroupsOnly(t *testing.T) {
	sc := &Scenario{
		Name: "x",
		Groups: []Group{
			{Name: "g1", Events: []string{"a", "b"}},
			{Name: "g2", Events: []string{"c"}},
		},
	}
	got := FlattenScenario(sc)
	want := []string{"a", "b", "c"}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("FlattenScenario(groups only): got %v, want %v", got, want)
	}
}

func TestFlattenScenario_EventsAndGroups(t *testing.T) {
	sc := &Scenario{
		Name:   "x",
		Events: []string{"first"},
		Groups: []Group{
			{Events: []string{"second", "third"}},
		},
	}
	got := FlattenScenario(sc)
	want := []string{"first", "second", "third"}
	if len(got) != 3 || got[0] != "first" || got[1] != "second" || got[2] != "third" {
		t.Errorf("FlattenScenario(events and groups): got %v, want %v", got, want)
	}
}

func TestFlattenScenario_Empty(t *testing.T) {
	sc := &Scenario{Name: "x"}
	got := FlattenScenario(sc)
	if got != nil {
		t.Errorf("FlattenScenario(empty): got %v, want nil", got)
	}
}

func TestResolveScenarios_AllScenarios_SingleSuite(t *testing.T) {
	suites, err := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, err := ResolveScenarios(suites, nil, true)
	if err != nil {
		t.Fatalf("ResolveScenarios: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 scenarios, got %d", len(got))
	}
	if got[0].Name != "smoke" || got[1].Name != "filesystem" {
		t.Errorf("order: got %q, %q", got[0].Name, got[1].Name)
	}
}

func TestResolveScenarios_AllScenarios_MultipleSuites_LastWins(t *testing.T) {
	suites, err := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml", "testdata/suite_second.yaml"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, err := ResolveScenarios(suites, nil, true)
	if err != nil {
		t.Fatalf("ResolveScenarios: %v", err)
	}
	// Order: first occurrence of each name; smoke appears in both, last wins (suite_second).
	// Names order from first file: smoke, filesystem; then second file: extra, smoke (overwrite).
	// So namesOrder = smoke, filesystem, extra (extra is new). Then byName[smoke] = second's smoke.
	if len(got) != 3 {
		t.Fatalf("expected 3 scenarios (smoke, filesystem, extra), got %d", len(got))
	}
	// resolveAllScenarios: we iterate suite1 (smoke, filesystem), suite2 (extra, smoke). namesOrder = smoke, filesystem, extra. byName[smoke]=2nd, byName[filesystem]=1st, byName[extra]=2nd.
	if got[0].Name != "smoke" || got[1].Name != "filesystem" || got[2].Name != "extra" {
		t.Errorf("order: got %q, %q, %q", got[0].Name, got[1].Name, got[2].Name)
	}
	// Smoke should be the one from suite_second (only one event: ptrace).
	if len(got[0].Events) != 1 || got[0].Events[0] != "ptrace" {
		t.Errorf("smoke should be last-wins from suite_second: got %v", got[0].Events)
	}
}

func TestResolveScenarios_ByName_One(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	got, err := ResolveScenarios(suites, []string{"filesystem"}, false)
	if err != nil {
		t.Fatalf("ResolveScenarios: %v", err)
	}
	if len(got) != 1 || got[0].Name != "filesystem" {
		t.Errorf("expected [filesystem], got %v", scenarioNames(got))
	}
}

func TestResolveScenarios_ByName_Multiple(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	got, err := ResolveScenarios(suites, []string{"filesystem", "smoke"}, false)
	if err != nil {
		t.Fatalf("ResolveScenarios: %v", err)
	}
	if len(got) != 2 || got[0].Name != "filesystem" || got[1].Name != "smoke" {
		t.Errorf("expected [filesystem smoke], got %v", scenarioNames(got))
	}
}

func TestResolveScenarios_ByName_NotFound(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	_, err := ResolveScenarios(suites, []string{"nonexistent"}, false)
	if err == nil {
		t.Fatal("expected error for missing scenario")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention scenario name: %v", err)
	}
}

func TestResolveScenarios_SingleImplicit_OneScenario(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid_single_scenario.yaml"})
	got, err := ResolveScenarios(suites, nil, false)
	if err != nil {
		t.Fatalf("ResolveScenarios: %v", err)
	}
	if len(got) != 1 || got[0].Name != "only" {
		t.Errorf("expected single scenario only, got %v", scenarioNames(got))
	}
}

func TestResolveScenarios_SingleImplicit_MultipleScenarios_Error(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	_, err := ResolveScenarios(suites, nil, false)
	if err == nil {
		t.Fatal("expected error when multiple scenarios and no selection")
	}
	if !strings.Contains(err.Error(), "multiple scenarios") {
		t.Errorf("error should mention multiple scenarios: %v", err)
	}
}

func TestResolveScenarios_MutualExclusion(t *testing.T) {
	suites, _ := LoadSuitesFromFiles([]string{"testdata/suite_valid.yaml"})
	_, err := ResolveScenarios(suites, []string{"smoke"}, true)
	if err == nil {
		t.Fatal("expected error when both --scenario and --all-scenarios")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutually exclusive: %v", err)
	}
}

func scenarioNames(scenarios []*Scenario) []string {
	names := make([]string, len(scenarios))
	for i, s := range scenarios {
		names[i] = s.Name
	}
	return names
}
