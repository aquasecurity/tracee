package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
)

// EventDeps is the dependency tree of an event (event -> the events it depends on), with probe/ksymbol
// annotations. Detector and derived events expand into the base events they need.
type EventDeps struct {
	Event      string      `json:"event"`
	KSymbols   []string    `json:"ksymbols,omitempty"`
	ProbeCount int         `json:"probe_count,omitempty"`
	DependsOn  []EventDeps `json:"depends_on,omitempty"`
}

// PrintEventDeps prints the dependency graph of each named event in the given format ("tree", "mermaid",
// or "json"). Output goes to stdout.
func PrintEventDeps(eventNames []string, format string) error {
	return PrintEventDepsTo(os.Stdout, eventNames, format)
}

// PrintEventDepsTo is PrintEventDeps with an explicit writer (for testing).
func PrintEventDepsTo(w io.Writer, eventNames []string, format string) error {
	roots := make([]EventDeps, 0, len(eventNames))
	for _, name := range eventNames {
		id, ok := events.Core.GetDefinitionIDByName(name)
		if !ok {
			return fmt.Errorf("unknown event: %q", name)
		}
		roots = append(roots, buildEventDeps(id, map[events.ID]bool{}))
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(roots)
	case "mermaid":
		return printDepsMermaid(w, roots)
	case "tree", "":
		for _, r := range roots {
			printDepsTree(w, r, 0)
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (use tree, mermaid, or json)", format)
	}
}

// buildEventDeps builds the dependency tree for id. visited is a per-path cycle guard (dependency graphs
// are DAGs; the guard only prevents pathological loops, and lets a shared dependency appear under each
// branch that needs it).
func buildEventDeps(id events.ID, visited map[events.ID]bool) EventDeps {
	def := events.Core.GetDefinitionByID(id)
	node := EventDeps{Event: def.GetName()}

	deps := def.GetDependencies().GetPrimaryDependencies()
	for _, ks := range deps.GetKSymbols() {
		node.KSymbols = append(node.KSymbols, ks.GetSymbolName())
	}
	node.ProbeCount = len(deps.GetProbes())

	if visited[id] {
		return node
	}
	visited[id] = true
	defer delete(visited, id)

	depIDs := deps.GetIDs()
	sort.Slice(depIDs, func(i, j int) bool { return depIDs[i] < depIDs[j] })
	for _, dep := range depIDs {
		node.DependsOn = append(node.DependsOn, buildEventDeps(dep, visited))
	}
	return node
}

func nodeAnnotation(n EventDeps) string {
	var ann []string
	if len(n.KSymbols) > 0 {
		ann = append(ann, "ksyms: "+strings.Join(n.KSymbols, ", "))
	}
	if n.ProbeCount > 0 {
		ann = append(ann, fmt.Sprintf("%d probe(s)", n.ProbeCount))
	}
	if len(ann) == 0 {
		return ""
	}
	return "  (" + strings.Join(ann, "; ") + ")"
}

// printDepsTree prints an ASCII (no box-drawing) indented tree.
func printDepsTree(w io.Writer, node EventDeps, depth int) {
	if depth == 0 {
		fmt.Fprintf(w, "%s%s\n", node.Event, nodeAnnotation(node))
	} else {
		fmt.Fprintf(w, "%s- %s%s\n", strings.Repeat("  ", depth), node.Event, nodeAnnotation(node))
	}
	for _, d := range node.DependsOn {
		printDepsTree(w, d, depth+1)
	}
}

// printDepsMermaid emits a fenced mermaid flowchart, ready to paste into the docs.
func printDepsMermaid(w io.Writer, roots []EventDeps) error {
	fmt.Fprintln(w, "```mermaid")
	fmt.Fprintln(w, "flowchart TD")
	seen := map[string]bool{}
	var walk func(n EventDeps)
	walk = func(n EventDeps) {
		if len(n.DependsOn) == 0 {
			if line := "    " + n.Event; !seen[line] {
				seen[line] = true
				fmt.Fprintln(w, line)
			}
			return
		}
		for _, d := range n.DependsOn {
			if edge := fmt.Sprintf("    %s --> %s", n.Event, d.Event); !seen[edge] {
				seen[edge] = true
				fmt.Fprintln(w, edge)
			}
			walk(d)
		}
	}
	for _, r := range roots {
		walk(r)
	}
	fmt.Fprintln(w, "```")
	return nil
}
