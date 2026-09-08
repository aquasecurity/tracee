package stress

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Suite represents a YAML event suite file.
// Top-level metadata is optional; Scenarios is required and must be non-empty.
type Suite struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Scenarios   []Scenario `yaml:"scenarios"`
}

// Scenario is a named set of event specs, optionally grouped.
// Name is required and must be unique within the file.
// At least one of Events or Groups must be non-empty.
type Scenario struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Events      []string `yaml:"events"`
	Groups      []Group  `yaml:"groups"`
}

// Group organizes event specs within a scenario.
// Purely organizational; execution flattens to a single list.
type Group struct {
	Name   string   `yaml:"name"`
	Events []string `yaml:"events"`
}

// LoadSuitesFromFiles reads and parses YAML suite files.
// Returns one *Suite per path in the same order. On first error (file not found,
// invalid YAML, or validation failure), returns an error that includes the path.
func LoadSuitesFromFiles(paths []string) ([]*Suite, error) {
	result := make([]*Suite, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var s Suite
		if err := yaml.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := validateSuite(&s, path); err != nil {
			return nil, err
		}
		result = append(result, &s)
	}
	return result, nil
}

// FlattenScenario returns a single slice of event specs: s.Events first, then
// each group's Events in order. Preserves order; no deduplication.
func FlattenScenario(s *Scenario) []string {
	var out []string
	if len(s.Events) > 0 {
		out = append(out, s.Events...)
	}
	for i := range s.Groups {
		out = append(out, s.Groups[i].Events...)
	}
	return out
}

// ResolveScenarios returns the scenarios to run based on suite load and flags.
// If allScenarios is true, returns all scenarios (suite order, then scenario order).
// If scenarioNames is non-empty, returns those scenarios by name in the requested order.
// In both cases, when multiple suites define a scenario with the same name, the
// last-loaded suite wins (later files override earlier ones, like config layering).
// If neither flag is set, returns the single scenario when exactly one exists; otherwise error.
func ResolveScenarios(suites []*Suite, scenarioNames []string, allScenarios bool) ([]*Scenario, error) {
	if allScenarios && len(scenarioNames) > 0 {
		return nil, errors.New("--scenario and --all-scenarios are mutually exclusive")
	}
	if allScenarios {
		return resolveAllScenarios(suites), nil
	}
	if len(scenarioNames) > 0 {
		return resolveScenariosByName(suites, scenarioNames)
	}
	return resolveSingleImplicit(suites)
}

func resolveAllScenarios(suites []*Suite) []*Scenario {
	var namesOrder []string
	byName := make(map[string]*Scenario)
	for _, s := range suites {
		for i := range s.Scenarios {
			sc := &s.Scenarios[i]
			if byName[sc.Name] == nil {
				namesOrder = append(namesOrder, sc.Name)
			}
			byName[sc.Name] = sc
		}
	}
	out := make([]*Scenario, 0, len(namesOrder))
	for _, n := range namesOrder {
		out = append(out, byName[n])
	}
	return out
}

func resolveScenariosByName(suites []*Suite, names []string) ([]*Scenario, error) {
	// Build a map of scenario name -> last occurrence (last-loaded suite wins).
	byName := make(map[string]*Scenario)
	for _, s := range suites {
		for i := range s.Scenarios {
			byName[s.Scenarios[i].Name] = &s.Scenarios[i]
		}
	}
	out := make([]*Scenario, 0, len(names))
	for _, name := range names {
		sc, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("scenario %q not found", name)
		}
		out = append(out, sc)
	}
	return out, nil
}

func resolveSingleImplicit(suites []*Suite) ([]*Scenario, error) {
	var all []*Scenario
	for _, s := range suites {
		for i := range s.Scenarios {
			all = append(all, &s.Scenarios[i])
		}
	}
	if len(all) == 1 {
		return all, nil
	}
	if len(all) == 0 {
		return nil, errors.New("no scenarios in loaded files")
	}
	var names []string
	seen := make(map[string]struct{})
	for _, sc := range all {
		if _, ok := seen[sc.Name]; !ok {
			seen[sc.Name] = struct{}{}
			names = append(names, sc.Name)
		}
	}
	return nil, fmt.Errorf("multiple scenarios available: specify --scenario or --all-scenarios (e.g. --scenario %s)", strings.Join(names, ", "))
}

// validateSuite checks suite rules.
func validateSuite(s *Suite, path string) error {
	if len(s.Scenarios) == 0 {
		return fmt.Errorf("%s: at least one scenario is required", path)
	}
	seen := make(map[string]struct{})
	for i := range s.Scenarios {
		sc := &s.Scenarios[i]
		if sc.Name == "" {
			return fmt.Errorf("%s: scenario at index %d has no name", path, i)
		}
		if _, ok := seen[sc.Name]; ok {
			return fmt.Errorf("%s: duplicate scenario name %q", path, sc.Name)
		}
		seen[sc.Name] = struct{}{}
		hasEvents := len(sc.Events) > 0
		hasGroups := false
		for g := range sc.Groups {
			if len(sc.Groups[g].Events) > 0 {
				hasGroups = true
				break
			}
		}
		if !hasEvents && !hasGroups {
			return fmt.Errorf("%s: scenario %q must have at least one of events or groups", path, sc.Name)
		}
	}
	return nil
}
