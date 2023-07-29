package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func PrintEventList(includeSigs bool, wideOutput bool) {
	// TODO: Create String() method in types trace.ArgMeta
	paramsToString := func(params []trace.ArgMeta) string {
		strSlice := []string{}
		for _, p := range params {
			strSlice = append(strSlice, p.Type+" "+p.Name)
		}
		return strings.Join(strSlice, ", ")
	}

	allDefinitions := events.Core.GetDefinitions()

	// Use tablewriter to print events in a table
	newTable := func() *tablewriter.Table {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Rule", "Sets", "Arguments"})
		table.SetColMinWidth(0, 15)
		table.SetColMinWidth(1, 15)
		table.SetColMinWidth(2, 40)
		table.SetAutoWrapText(!wideOutput)
		table.SetRowLine(!wideOutput)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderLine(true)
		table.SetBorder(true)
		return table
	}

	tableRender := func(table *tablewriter.Table, title string) *tablewriter.Table {
		fmt.Printf("\n" + title + "\n\n")
		table.Render()
		return newTable()
	}

	getRow := func(evtDef events.Definition) []string {
		return []string{
			evtDef.GetName(),
			strings.Join(evtDef.GetSets(), ", "),
			paramsToString(evtDef.GetParams()),
		}
	}

	fmt.Printf("Tracee supports the following events (use --wide for wider output):\n")
	table := newTable()

	// Signature Events
	for _, evtDef := range allDefinitions {
		if evtDef.IsSignature() {
			table.AppendBulk([][]string{getRow(evtDef)})
		}
	}
	table = tableRender(table, "Signature Events")

	// Syscall Events
	for _, evtDef := range allDefinitions {
		if evtDef.IsSyscall() {
			table.AppendBulk([][]string{getRow(evtDef)})
		}
	}
	table = tableRender(table, "Syscall Events")

	// Other Events
	for _, evtDef := range allDefinitions {
		if !evtDef.IsInternal() && !evtDef.IsSyscall() &&
			!evtDef.IsSignature() && !evtDef.IsNetwork() {
			table.AppendBulk([][]string{getRow(evtDef)})
		}
	}
	table = tableRender(table, "Other Events")

	// Network Events
	for _, evtDef := range allDefinitions {
		if evtDef.IsNetwork() {
			table.AppendBulk([][]string{getRow(evtDef)})
		}
	}
	tableRender(table, "Network Events")
}
