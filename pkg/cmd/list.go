package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// EventInfo represents event information for JSON output.
type EventInfo struct {
	Name        string   `json:"name"`
	ID          int      `json:"id"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags"`
	Type        string   `json:"type"`
	Arguments   []string `json:"arguments,omitempty"`
}

// DetectorInfo represents detector information for JSON output.
type DetectorInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	RequiredEvents []string `json:"required_events,omitempty"`
	MITRETactic    string   `json:"mitre_tactic,omitempty"`
	MITRETechnique string   `json:"mitre_technique,omitempty"`
}

// PolicyInfo represents policy information for JSON output.
type PolicyInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scope       []string `json:"scope,omitempty"`
	RuleCount   int      `json:"rule_count"`
}

// PrintEventList prints filtered events in table or JSON format to stdout.
func PrintEventList(filters flags.EventListFilters, jsonOutput bool) error {
	return PrintEventListTo(os.Stdout, filters, jsonOutput)
}

// PrintEventListTo prints filtered events in table or JSON format to the given writer.
func PrintEventListTo(w io.Writer, filters flags.EventListFilters, jsonOutput bool) error {
	allDefinitions := events.Core.GetDefinitions()

	// Filter events
	var filteredEvents []events.Definition
	for _, def := range allDefinitions {
		// Skip internal events
		if def.IsInternal() {
			continue
		}
		// Apply filters
		if filters.MatchesEvent(def) {
			filteredEvents = append(filteredEvents, def)
		}
	}

	if jsonOutput {
		return printEventsJSON(w, filteredEvents)
	}
	return printEventsTable(w, filteredEvents, filters.HasFilters())
}

// printEventsJSON outputs events in JSON format.
func printEventsJSON(w io.Writer, defs []events.Definition) error {
	eventInfos := make([]EventInfo, 0, len(defs))
	for _, def := range defs {
		eventInfos = append(eventInfos, EventInfo{
			Name:        def.GetName(),
			ID:          int(def.GetID()),
			Version:     def.GetVersion().String(),
			Description: def.GetDescription(),
			Tags:        def.GetSets(),
			Type:        getEventType(def),
			Arguments:   fieldsToStrings(def.GetFields()),
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(eventInfos)
}

// printEventsTable outputs events in table format.
func printEventsTable(w io.Writer, defs []events.Definition, hasFilters bool) error {
	if len(defs) == 0 {
		fmt.Fprintln(w, "No events match the specified filters.")
		return nil
	}

	// Group events by type for display
	var syscalls, detectors, network, other []events.Definition
	for _, def := range defs {
		switch {
		case def.IsSyscall():
			syscalls = append(syscalls, def)
		case def.IsDetector():
			detectors = append(detectors, def)
		case def.IsNetwork():
			network = append(network, def)
		default:
			other = append(other, def)
		}
	}

	if hasFilters {
		fmt.Fprintf(w, "Showing %d events matching filters:\n", len(defs))
	} else {
		fmt.Fprintln(w, "Tracee supports the following events:")
	}

	table := newEventTable(w)

	// Print each category if it has events
	if len(detectors) > 0 {
		table = renderEventSection(w, table, detectors, "Detector Events")
	}
	if len(syscalls) > 0 {
		table = renderEventSection(w, table, syscalls, "Syscall Events")
	}
	if len(other) > 0 {
		table = renderEventSection(w, table, other, "Other Events")
	}
	if len(network) > 0 {
		renderEventSection(w, table, network, "Network Events")
	}

	return nil
}

// newEventTable creates a new table writer for events.
func newEventTable(w io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"Event", "Tags", "Arguments"})
	table.SetColMinWidth(0, 20)
	table.SetColMinWidth(1, 20)
	table.SetColMinWidth(2, 40)
	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetBorder(true)
	return table
}

// renderEventSection prints a section of events and returns a new table.
func renderEventSection(w io.Writer, table *tablewriter.Table, defs []events.Definition, title string) *tablewriter.Table {
	for _, def := range defs {
		table.Append([]string{
			def.GetName(),
			strings.Join(def.GetSets(), ", "),
			strings.Join(fieldsToStrings(def.GetFields()), ", "),
		})
	}
	fmt.Fprintf(w, "\n%s (%d)\n\n", title, len(defs))
	table.Render()
	return newEventTable(w)
}

// PrintDetectorList prints detectors in table or JSON format to stdout.
func PrintDetectorList(detectorsList []detection.EventDetector, jsonOutput bool) error {
	return PrintDetectorListTo(os.Stdout, detectorsList, jsonOutput)
}

// PrintDetectorListTo prints detectors in table or JSON format to the given writer.
func PrintDetectorListTo(w io.Writer, detectorsList []detection.EventDetector, jsonOutput bool) error {
	if jsonOutput {
		return printDetectorsJSON(w, detectorsList)
	}
	return printDetectorsTable(w, detectorsList)
}

// printDetectorsJSON outputs detectors in JSON format.
func printDetectorsJSON(w io.Writer, detectorsList []detection.EventDetector) error {
	infos := make([]DetectorInfo, 0, len(detectorsList))
	for _, det := range detectorsList {
		def := det.GetDefinition()
		info := DetectorInfo{
			ID:          def.ID,
			Name:        def.ProducedEvent.Name,
			Description: def.ProducedEvent.Description,
		}

		// Extract required events
		for _, req := range def.Requirements.Events {
			info.RequiredEvents = append(info.RequiredEvents, req.Name)
		}

		// Extract threat metadata if available
		if def.ThreatMetadata != nil {
			info.Severity = def.ThreatMetadata.Severity.String()
			if def.ThreatMetadata.Mitre != nil {
				if def.ThreatMetadata.Mitre.Tactic != nil {
					info.MITRETactic = def.ThreatMetadata.Mitre.Tactic.Name
				}
				if def.ThreatMetadata.Mitre.Technique != nil {
					info.MITRETechnique = def.ThreatMetadata.Mitre.Technique.Id
				}
			}
		}

		infos = append(infos, info)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(infos)
}

// printDetectorsTable outputs detectors in table format.
func printDetectorsTable(w io.Writer, detectorsList []detection.EventDetector) error {
	if len(detectorsList) == 0 {
		fmt.Fprintln(w, "No detectors found.")
		return nil
	}

	fmt.Fprintf(w, "Available detectors (%d):\n\n", len(detectorsList))

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"ID", "Name", "Severity", "Required Events", "MITRE"})
	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetBorder(true)

	for _, det := range detectorsList {
		def := det.GetDefinition()

		severity := ""
		mitre := ""
		if def.ThreatMetadata != nil {
			severity = def.ThreatMetadata.Severity.String()
			if def.ThreatMetadata.Mitre != nil && def.ThreatMetadata.Mitre.Technique != nil {
				mitre = def.ThreatMetadata.Mitre.Technique.Id
			}
		}

		requiredEvents := make([]string, 0, len(def.Requirements.Events))
		for _, req := range def.Requirements.Events {
			requiredEvents = append(requiredEvents, req.Name)
		}

		table.Append([]string{
			def.ID,
			def.ProducedEvent.Name,
			severity,
			strings.Join(requiredEvents, ", "),
			mitre,
		})
	}

	table.Render()
	return nil
}

// PrintPolicyList prints policies in table or JSON format to stdout.
func PrintPolicyList(policies []k8s.PolicyInterface, jsonOutput bool) error {
	return PrintPolicyListTo(os.Stdout, policies, jsonOutput)
}

// PrintPolicyListTo prints policies in table or JSON format to the given writer.
func PrintPolicyListTo(w io.Writer, policies []k8s.PolicyInterface, jsonOutput bool) error {
	if jsonOutput {
		return printPoliciesJSON(w, policies)
	}
	return printPoliciesTable(w, policies)
}

// printPoliciesJSON outputs policies in JSON format.
func printPoliciesJSON(w io.Writer, policies []k8s.PolicyInterface) error {
	infos := make([]PolicyInfo, 0, len(policies))
	for _, pol := range policies {
		info := PolicyInfo{
			Name:        pol.GetName(),
			Description: pol.GetDescription(),
			Scope:       pol.GetScope(),
			RuleCount:   len(pol.GetRules()),
		}
		infos = append(infos, info)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(infos)
}

// printPoliciesTable outputs policies in table format.
func printPoliciesTable(w io.Writer, policies []k8s.PolicyInterface) error {
	if len(policies) == 0 {
		fmt.Fprintln(w, "No policies found.")
		return nil
	}

	fmt.Fprintf(w, "Available policies (%d):\n\n", len(policies))

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"Name", "Description", "Scope", "Rules"})
	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(true)
	table.SetBorder(true)

	for _, pol := range policies {
		scopeSummary := strings.Join(pol.GetScope(), ", ")
		if len(scopeSummary) > 50 {
			scopeSummary = scopeSummary[:47] + "..."
		}

		table.Append([]string{
			pol.GetName(),
			pol.GetDescription(),
			scopeSummary,
			fmt.Sprintf("%d", len(pol.GetRules())),
		})
	}

	table.Render()
	return nil
}

// Helper functions

func getEventType(def events.Definition) string {
	switch {
	case def.IsSyscall():
		return "syscall"
	case def.IsDetector():
		return "detector"
	case def.IsNetwork():
		return "network"
	default:
		return "other"
	}
}

func fieldsToStrings(fields []events.DataField) []string {
	result := make([]string, 0, len(fields))
	for _, f := range fields {
		result = append(result, f.Type+" "+f.Name)
	}
	return result
}
